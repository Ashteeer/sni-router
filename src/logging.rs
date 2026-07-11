//! `tracing` initialization.
//!
//! Runtime-agnostic subscriber (no tokio). The level comes from config, with a
//! bare `RUST_LOG` value (`RUST_LOG=debug`) taking precedence for ad-hoc
//! debugging. `env-filter`/`regex` are intentionally not pulled in — a single
//! process-wide level is all this service needs.

use crate::config::{Log, LogFormat};
use tracing::Level;

/// Install the global tracing subscriber. Call once at startup (run mode only).
pub fn init(cfg: &Log) {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| parse_level(&v))
        .or_else(|| parse_level(&cfg.level))
        .unwrap_or(Level::INFO);

    let builder = tracing_subscriber::fmt().with_max_level(level);
    match cfg.format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

/// Parse a bare level word (`info`, `debug`, ...). Returns `None` for anything
/// else so a directive-style `RUST_LOG` doesn't silently disable logging.
pub fn parse_level(s: &str) -> Option<Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "error" => Some(Level::ERROR),
        "warn" | "warning" => Some(Level::WARN),
        "info" => Some(Level::INFO),
        "debug" => Some(Level::DEBUG),
        "trace" => Some(Level::TRACE),
        _ => None,
    }
}
