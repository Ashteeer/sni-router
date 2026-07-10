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
    /// First match wins.
    pub routes: Vec<Route>,
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
    /// Required (and only used) when `mode: terminate`.
    pub tls: Option<Tls>,
    /// Injected HTTP headers; only applied when `mode: terminate`.
    #[serde(default)]
    pub headers: Headers,
    /// Backend addresses, `IP:port`. Address family is independent from the
    /// listener's (IPv6 client -> IPv4 backend works in passthrough).
    pub servers: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Passthrough,
    Terminate,
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

#[derive(Debug, Default, Deserialize, Serialize)]
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
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { handshake: 5, connect: 10, idle: 300 }
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
