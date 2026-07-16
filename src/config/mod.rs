//! Configuration: YAML structures, parsing and path resolution.
//!
//! Kept flat and predictable on purpose — a future web UI will generate this
//! file programmatically, so no YAML anchors/merge keys are required anywhere.

pub mod validate;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Default config location. Overridable via CLI arg or [`CONFIG_ENV_VAR`]
/// (the env var matters for snap confinement, where the real path lives
/// under `$SNAP_DATA`).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/sni-router/sni-router.yaml";
/// Environment variable that overrides the default config path.
pub const CONFIG_ENV_VAR: &str = "SNI_ROUTER_CONFIG";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Empty is valid: an API-only config that carries no routing yet (a web UI
    /// fills in listeners/backends later via `PUT /config`).
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub backends: BTreeMap<String, Backend>,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub limits: Limits,
    /// Unified management + metrics API: one `IP:port`, one token. Serves the
    /// control plane (config read/write, reload, restart) and `GET /metrics`.
    /// Foundation for a web UI.
    #[serde(default)]
    pub api: Option<Api>,
    /// Logging configuration.
    #[serde(default)]
    pub log: Log,
    /// Shared TLS certificate used by every `terminate`/`terminate_tcp` backend
    /// that doesn't set its own `tls`. Lets you point many backends at one
    /// wildcard cert without repeating the paths. A backend's own `tls` always
    /// wins over this.
    #[serde(default)]
    pub default_tls: Option<Tls>,
}

impl Config {
    /// Effective TLS cert/key for a backend: its own `tls` if set, else the
    /// shared `default_tls`.
    pub fn effective_tls<'a>(&'a self, b: &'a Backend) -> Option<&'a Tls> {
        b.tls.as_ref().or(self.default_tls.as_ref())
    }

    /// Effective TLS cert/key for the API: `api.tls` if set, else the shared
    /// `default_tls`. `None` = serve plaintext HTTP.
    pub fn effective_api_tls(&self) -> Option<&Tls> {
        self.api
            .as_ref()
            .and_then(|a| a.tls.as_ref())
            .or(self.default_tls.as_ref())
    }
}

/// Logging: level and output format.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// `error` | `warn` | `info` | `debug` | `trace`. A bare `RUST_LOG` level
    /// overrides this at startup.
    pub level: String,
    /// `text` (human-readable) or `json` (one JSON object per line).
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Self { level: "info".into(), format: LogFormat::default() }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Unified management + metrics HTTP API. One bind, one token guards every
/// endpoint. Reads: `GET /status`, `GET /config`, `GET /healthz`,
/// `GET /metrics`. Writes: `PUT /config`, `POST /reload`, `POST /restart`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// Address to serve the API on, e.g. `0.0.0.0:9000`. Reachable by a remote
    /// web UI; protect it with a `token` (and ideally `tls`).
    pub bind: String,
    /// Bearer token; when set, **every** request (reads and writes) must send
    /// `Authorization: Bearer <token>`. Never echoed back by `GET /config`.
    /// **Required for the write endpoints** — without it they return 403, so
    /// the config can't be changed unauthenticated.
    #[serde(default, skip_serializing)]
    pub token: Option<String>,
    /// Serve the API over HTTPS with this cert/key. If omitted, the top-level
    /// `default_tls` is used; if neither is set, the API is plaintext HTTP.
    /// A cert change is picked up on the next restart (not hot-reloaded).
    #[serde(default)]
    pub tls: Option<Tls>,
}

/// A listener only decides how client connections are accepted (`bind`, `proto`).
/// How the backend is talked to (`mode`, `proxy_protocol`, balancing) lives in
/// [`Backend`] — deliberate separation, see project docs.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub name: String,
    /// One or more `IP:port` accept addresses (e.g. IPv4 + IPv6 side by side).
    pub bind: Vec<String>,
    #[serde(default)]
    pub proto: Proto,
    /// `listen(2)` backlog: how many completed-handshake connections may wait
    /// for `accept`. Absent = [`DEFAULT_QUEUE`]. Overflow drops SYNs, so raise
    /// it for bursty reconnects. Capped by `net.core.somaxconn`. `tcp` only.
    #[serde(default)]
    pub backlog: Option<u32>,
    /// Accept TCP Fast Open connections (`TCP_FASTOPEN`), letting returning
    /// clients send the ClientHello inside the SYN. `proto: tcp` only; requires
    /// `net.ipv4.tcp_fastopen` to have the server bit set (sysctl 2 or 3).
    /// Outgoing connections to backends are unaffected.
    #[serde(default)]
    pub fast_open: bool,
    /// Max pending TFO SYNs (connections whose data arrived but whose handshake
    /// has not completed). Absent = [`DEFAULT_QUEUE`]. Overflow is not a
    /// failure: the client silently falls back to a normal handshake.
    #[serde(default)]
    pub fast_open_qlen: Option<u32>,
    /// Optional access control for this listener (by client IP and/or SNI).
    #[serde(default)]
    pub acl: Option<AclConfig>,
    /// First match wins.
    pub routes: Vec<Route>,
}

/// Default depth for both accept queues (`listen()` backlog and TFO qlen).
/// Sized for a reconnect burst: a queue holds roughly `new_conns_per_sec × RTT`
/// entries, so 1024 covers ~1000 conn/s at a 200 ms RTT (~1.5 MB worst case for
/// the TFO queue, which also holds the SYN payload).
pub const DEFAULT_QUEUE: u32 = 1024;

impl Listener {
    /// `listen()` backlog for this listener.
    pub fn backlog(&self) -> u32 {
        self.backlog.unwrap_or(DEFAULT_QUEUE)
    }

    /// TFO pending-SYN queue depth for this listener.
    pub fn fast_open_qlen(&self) -> u32 {
        self.fast_open_qlen.unwrap_or(DEFAULT_QUEUE)
    }
}

/// Raw access-control lists (strings); compiled into [`crate::acl::Acl`] at
/// startup. An empty allow list means "allow all" for that dimension; deny
/// always wins.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AclConfig {
    /// Client IPs/CIDRs permitted (empty = any).
    pub allow_ip: Vec<String>,
    /// Client IPs/CIDRs rejected.
    pub deny_ip: Vec<String>,
    /// SNI patterns permitted (empty = any); same wildcard rules as routes.
    pub allow_sni: Vec<String>,
    /// SNI patterns rejected.
    pub deny_sni: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Exact name (`example.com`), wildcard (`*.example.com`, any subdomain
    /// depth, apex not included) or catch-all (`*`).
    pub sni: String,
    /// Name of an entry in the top-level `backends` section.
    pub backend: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    /// UDP listener = QUIC passthrough.
    Udp,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub proxy_protocol: ProxyProtocol,
    #[serde(default)]
    pub balance: Balance,
    #[serde(default)]
    pub health_check: bool,
    /// Use TCP Fast Open when connecting to this backend's servers, saving one
    /// RTT on repeat connects (`TCP_FASTOPEN_CONNECT`; the SYN carries the first
    /// write). Off by default: it only pays off when the server is a remote hop
    /// **and** has TFO enabled itself — for a local backend the RTT it saves is
    /// already ~0. Ignored on the udp path (no TCP connect) and by
    /// `redirect_https` (no backend at all).
    #[serde(default)]
    pub fast_open: bool,
    /// Cert/key the router presents to clients for `terminate`/`terminate_tcp`.
    /// Optional: if omitted, the top-level `default_tls` is used instead.
    pub tls: Option<Tls>,
    /// When set (terminate mode only), the router re-encrypts to the backend
    /// over TLS instead of forwarding plaintext. Absent = plaintext to backend.
    #[serde(default)]
    pub backend_tls: Option<BackendTls>,
    /// Injected HTTP headers; only applied when `mode: terminate`.
    #[serde(default)]
    pub headers: Headers,
    /// Advertise HTTP/2 (`h2`) ALPN and terminate it (terminate mode only).
    /// h2 requests are gatewayed to the backend over HTTP/1.1 plaintext, so it
    /// is not combinable with `backend_tls`.
    #[serde(default)]
    pub http2: bool,
    /// Optional per-path request rules (terminate mode only): forward matching
    /// paths to the backend, answer others with a synthetic response. First
    /// match wins; if empty, every request is forwarded. Envoy-style DoH:
    /// `/dns-query` -> forward, `*` -> 404.
    #[serde(default)]
    pub http_rules: Vec<HttpRule>,
    /// Backend addresses, `IP:port`. Address family is independent from the
    /// listener's (IPv6 client -> IPv4 backend works in passthrough). Empty is
    /// only valid for `mode: redirect_https`.
    #[serde(default)]
    pub servers: Vec<String>,
}

/// One HTTP request rule, matched by URL path prefix. Rules work the same way
/// on any HTTP-serving backend — `terminate` (over TLS) and `redirect_https`
/// (plaintext) — so a redirect (301) or a direct response (404) can be placed
/// wherever it is needed, not bound to a specific port or mode.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRule {
    /// Path prefix to match (`/dns-query`), or `*` for catch-all.
    pub path: String,
    pub action: HttpAction,
    /// `respond`: HTTP status (required). `redirect`: optional (default 301).
    pub status: Option<u16>,
    /// `respond`: optional response body.
    #[serde(default)]
    pub body: String,
    /// `respond`: `Content-Type` (default `text/plain`).
    pub content_type: Option<String>,
    /// `redirect`: where to send the client (required for `redirect`). Either
    /// the literal `https` (redirect to the `https://` URL for the same host and
    /// path — the http->https upgrade) or an absolute URL like
    /// `https://example.com/new`.
    pub to: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAction {
    /// Forward the request to this backend's servers.
    Forward,
    /// Answer directly with a synthetic response (status + optional body).
    Respond,
    /// Answer with an HTTP redirect (3xx + `Location`).
    Redirect,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Passthrough,
    /// Terminate TLS and forward to the backend as HTTP/1.1 (with header
    /// injection, optional re-encrypt, and optional path rules).
    Terminate,
    /// Terminate TLS and forward the decrypted stream to the backend as **raw
    /// TCP** (not HTTP) — e.g. DoT on `:853`. Optional PROXY protocol.
    TerminateTcp,
    /// Answer plaintext HTTP with a `301` to the `https://` equivalent. No
    /// backend servers; intended for a `:80` listener.
    RedirectHttps,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    None,
    V1,
    V2,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastConn,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Backend-side TLS for terminate mode (re-encrypt, optional mTLS).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BackendTls {
    /// ServerName sent (and verified) to the backend. Defaults to the client's
    /// requested SNI if unset.
    pub sni: Option<String>,
    /// Skip backend certificate verification (dangerous; test/self-signed only).
    pub insecure_skip_verify: bool,
    /// Trust this CA (PEM) for the backend cert instead of the built-in roots.
    pub ca: Option<PathBuf>,
    /// mTLS: client certificate the router presents to the backend.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Headers {
    #[serde(default)]
    pub x_real_ip: bool,
    #[serde(default)]
    pub x_forwarded_for: bool,
    #[serde(default)]
    pub x_forwarded_proto: bool,
}

impl Headers {
    pub fn any(&self) -> bool {
        self.x_real_ip || self.x_forwarded_for || self.x_forwarded_proto
    }
}

/// Global timeouts, seconds. All configurable — no magic numbers in code.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timeouts {
    /// Max time to read the full ClientHello (slowloris protection).
    pub handshake: u64,
    /// Backend connect timeout.
    pub connect: u64,
    /// Idle connection timeout.
    pub idle: u64,
    /// TCP keepalive idle time in seconds (0 = off), set on both client- and
    /// backend-facing sockets. The splice data path has no idle timeout — the
    /// kernel moves the bytes and never reports back — so keepalive is what
    /// reaps connections whose peer vanished without a FIN/RST (NAT rebind,
    /// dead VPN client). Probe interval and retry count are left to the system
    /// (`net.ipv4.tcp_keepalive_intvl`/`_probes`).
    pub keepalive: u64,
    /// How often to run backend health-check probes (for backends with
    /// `health_check: true`).
    pub health_interval: u64,
    /// Max time to wait for active connections to finish on SIGTERM before
    /// exiting (graceful drain).
    pub drain: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { handshake: 5, connect: 10, idle: 300, keepalive: 60, health_interval: 10, drain: 30 }
    }
}

/// Resource limits. Bound memory per pending connection independently of the
/// handshake timeout (a slow client shouldn't be able to buffer unbounded data
/// before we've even routed it).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Max bytes buffered while reassembling a TLS ClientHello.
    pub max_client_hello: usize,
    /// Max concurrent connections per client IP (0 = unlimited).
    pub max_conns_per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_client_hello: 16 * 1024, max_conns_per_ip: 0 }
    }
}

/// Resolve the config path: explicit CLI arg > `$SNI_ROUTER_CONFIG` > default.
pub fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(v) = std::env::var_os(CONFIG_ENV_VAR) {
        return Ok(PathBuf::from(v));
    }
    let default = Path::new(DEFAULT_CONFIG_PATH);
    if default.exists() {
        return Ok(default.to_path_buf());
    }
    Err(format!(
        "error: config file not found\n  \
         tried the default path: {DEFAULT_CONFIG_PATH}\n  \
         pass a path explicitly (sni-router -t /path/to/config.yaml)\n  \
         or set {CONFIG_ENV_VAR}=<path>"
    ))
}

/// Read and parse the config file. YAML/type errors come back with line:column
/// (serde location); semantic checks live in [`validate`].
pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read file: {e}", path.display()))?;
    parse_str(&text)
}

/// Parse a config from an in-memory YAML string (used by the admin write API,
/// which receives the config in the request body rather than from a file).
pub fn parse_str(text: &str) -> Result<Config, String> {
    serde_norway::from_str(text).map_err(|e| e.to_string())
}
