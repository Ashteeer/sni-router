//! Prometheus-compatible metrics.
//!
//! Counters are plain atomics (shared across all per-core workers, like the
//! balancing counters). [`render`] produces the Prometheus text; it's served by
//! the unified API handler at `GET /metrics` (same bind + token as the rest of
//! the control plane), so there's no separate exporter thread or port.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// Process-wide counters. `conns_active` is a gauge (inc/dec); the rest are
/// monotonic counters.
pub struct Global {
    pub conns_total: AtomicU64,
    pub conns_active: AtomicU64,
    pub conn_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub rate_limited: AtomicU64,
    pub udp_flows_total: AtomicU64,
    pub udp_datagrams: AtomicU64,
    /// h2 gateway streams served from a pooled backend connection (no connect).
    pub pool_hits: AtomicU64,
}

impl Global {
    const fn new() -> Self {
        Self {
            conns_total: AtomicU64::new(0),
            conns_active: AtomicU64::new(0),
            conn_errors: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            udp_flows_total: AtomicU64::new(0),
            udp_datagrams: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
        }
    }
}

/// The single process-wide metrics instance.
pub static GLOBAL: Global = Global::new();

/// Per-backend counters, kept in a name-keyed registry so counts survive a
/// SIGHUP reload (which rebuilds the pools but not the metric series).
#[derive(Default)]
pub struct Backend {
    pub conns_total: AtomicU64,
    pub conns_active: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

fn registry() -> &'static Mutex<BTreeMap<String, Arc<Backend>>> {
    static R: OnceLock<Mutex<BTreeMap<String, Arc<Backend>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Get (or lazily create) the counter set for a backend name.
pub fn backend(name: &str) -> Arc<Backend> {
    let mut m = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(b) = m.get(name) {
        return b.clone();
    }
    let b = Arc::new(Backend::default());
    m.insert(name.to_string(), b.clone());
    b
}

fn started() -> Instant {
    static S: OnceLock<Instant> = OnceLock::new();
    *S.get_or_init(Instant::now)
}

/// Pin the process start instant so `sni_router_uptime_seconds` counts from
/// startup, not from the first `/metrics` scrape. Call once at boot.
pub fn init() {
    started();
}

/// Render the current metrics in Prometheus text exposition format.
pub fn render() -> String {
    let g = &GLOBAL;
    let mut out = String::with_capacity(2048);

    macro_rules! metric {
        ($name:expr, $typ:expr, $help:expr, $val:expr) => {{
            out.push_str(&format!("# HELP {} {}\n", $name, $help));
            out.push_str(&format!("# TYPE {} {}\n", $name, $typ));
            out.push_str(&format!("{} {}\n", $name, $val));
        }};
    }

    metric!("sni_router_uptime_seconds", "gauge", "Process uptime.", started().elapsed().as_secs());
    metric!("sni_router_connections_total", "counter", "TCP connections routed to a backend.", g.conns_total.load(Ordering::Relaxed));
    metric!("sni_router_connections_active", "gauge", "TCP connections in flight.", g.conns_active.load(Ordering::Relaxed));
    metric!("sni_router_connection_errors_total", "counter", "Connections that ended in an error.", g.conn_errors.load(Ordering::Relaxed));
    metric!("sni_router_bytes_up_total", "counter", "Bytes forwarded client->backend.", g.bytes_up.load(Ordering::Relaxed));
    metric!("sni_router_bytes_down_total", "counter", "Bytes forwarded backend->client.", g.bytes_down.load(Ordering::Relaxed));
    metric!("sni_router_rate_limited_total", "counter", "Connections dropped by max_conns_per_ip.", g.rate_limited.load(Ordering::Relaxed));
    metric!("sni_router_udp_flows_total", "counter", "UDP/QUIC flows routed.", g.udp_flows_total.load(Ordering::Relaxed));
    metric!("sni_router_udp_datagrams_total", "counter", "UDP datagrams received.", g.udp_datagrams.load(Ordering::Relaxed));
    metric!("sni_router_h2_pool_hits_total", "counter", "h2 streams served from a pooled backend connection.", g.pool_hits.load(Ordering::Relaxed));

    // Per-backend series.
    let m = registry().lock().unwrap_or_else(|e| e.into_inner());
    if !m.is_empty() {
        out.push_str("# HELP sni_router_backend_connections_total Connections routed to a backend.\n");
        out.push_str("# TYPE sni_router_backend_connections_total counter\n");
        for (name, b) in m.iter() {
            out.push_str(&format!(
                "sni_router_backend_connections_total{{backend=\"{}\"}} {}\n",
                esc(name),
                b.conns_total.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP sni_router_backend_connections_active Active connections per backend.\n");
        out.push_str("# TYPE sni_router_backend_connections_active gauge\n");
        for (name, b) in m.iter() {
            out.push_str(&format!(
                "sni_router_backend_connections_active{{backend=\"{}\"}} {}\n",
                esc(name),
                b.conns_active.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP sni_router_backend_errors_total Errors per backend.\n");
        out.push_str("# TYPE sni_router_backend_errors_total counter\n");
        for (name, b) in m.iter() {
            out.push_str(&format!(
                "sni_router_backend_errors_total{{backend=\"{}\"}} {}\n",
                esc(name),
                b.errors.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP sni_router_backend_bytes_total Bytes per backend by direction.\n");
        out.push_str("# TYPE sni_router_backend_bytes_total counter\n");
        for (name, b) in m.iter() {
            out.push_str(&format!(
                "sni_router_backend_bytes_total{{backend=\"{}\",dir=\"up\"}} {}\n",
                esc(name),
                b.bytes_up.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "sni_router_backend_bytes_total{{backend=\"{}\",dir=\"down\"}} {}\n",
                esc(name),
                b.bytes_down.load(Ordering::Relaxed)
            ));
        }
    }

    out
}

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}
