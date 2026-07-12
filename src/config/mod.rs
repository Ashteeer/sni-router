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
    pub listeners: Vec<Listener>,
    pub backends: BTreeMap<String, Backend>,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub limits: Limits,
    /// Optional read-only admin/REST API (foundation for a future web UI).
    #[serde(default)]
    pub admin: Option<Admin>,
    /// Optional Prometheus metrics exporter.
    #[serde(default)]
    pub metrics: Option<MetricsExporter>,
    /// Logging configuration.
    #[serde(default)]
    pub log: Log,
}

/// Prometheus-compatible metrics exporter. Served by a tiny blocking HTTP
/// server on its own system thread, off the io_uring data path.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsExporter {
    /// Address to serve `GET /metrics` on, e.g. `127.0.0.1:9100`.
    pub bind: String,
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

/// Admin HTTP API. Read-only: `GET /status`, `GET /config`, `GET /healthz`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    /// Address to serve the admin API on, e.g. `127.0.0.1:9000`. Keep it on a
    /// loopback / trusted interface.
    pub bind: String,
    /// Optional bearer token; when set, requests must send
    /// `Authorization: Bearer <token>`. Never echoed back by `GET /config`.
    #[serde(default, skip_serializing)]
    pub token: Option<String>,
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
    /// Optional access control for this listener (by client IP and/or SNI).
    #[serde(default)]
    pub acl: Option<AclConfig>,
    /// First match wins.
    pub routes: Vec<Route>,
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
    /// Required (and only used) when `mode: terminate`: the cert/key the router
    /// presents to clients for server names routed to this backend.
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
    /// How often to run backend health-check probes (for backends with
    /// `health_check: true`).
    pub health_interval: u64,
    /// Max time to wait for active connections to finish on SIGTERM before
    /// exiting (graceful drain).
    pub drain: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { handshake: 5, connect: 10, idle: 300, health_interval: 10, drain: 30 }
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
    serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
