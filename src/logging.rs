//! `tracing` initialization.
//!
//! Runtime-agnostic subscriber (no tokio). The level comes from config, with a
//! bare `RUST_LOG` value (`RUST_LOG=debug`) taking precedence for ad-hoc
//! debugging. `env-filter`/`regex` are intentionally not pulled in — a single
//! process-wide level plus the dependency cap below is all this service needs.

use crate::config::{Log, LogFormat};
use std::io::IsTerminal;
use tracing::Level;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Dependency crates that log one line per protocol frame at `DEBUG`.
///
/// `log.level: debug` is meant to answer "what is this connection doing" — but
/// unfiltered it buries the router's own lines under h2 frame traffic, and on a
/// loaded server the volume *is* the outage: a line per frame from every core,
/// all serialising on one log writer. So `debug` means "the router's own
/// debug"; `trace` still lets everything through for protocol-level work.
const NOISY: &[&str] = &["monoio_http", "monoio", "h2", "rustls", "hyper", "want"];

/// Install the global tracing subscriber. Call once at startup (run mode only).
pub fn init(cfg: &Log) {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| parse_level(&v))
        .or_else(|| parse_level(&cfg.level))
        .unwrap_or(Level::INFO);

    let filter = FilterFn::new(move |meta| allow(meta.target(), *meta.level(), level));
    // Color only when stderr is a real terminal, so logs redirected to a file
    // or journald stay free of ANSI escapes.
    let ansi = std::io::stderr().is_terminal();
    let layer = tracing_subscriber::fmt::layer().with_ansi(ansi);
    match cfg.format {
        LogFormat::Text => tracing_subscriber::registry().with(layer.with_filter(filter)).init(),
        LogFormat::Json => {
            tracing_subscriber::registry().with(layer.json().with_filter(filter)).init()
        }
    }
}

/// Should an event from `target` at `level` be emitted, given the configured
/// maximum? Dependency frame-loggers are held at `INFO` unless the operator
/// asked for `trace` explicitly.
fn allow(target: &str, level: Level, max: Level) -> bool {
    if level > max {
        return false;
    }
    if max == Level::TRACE || level <= Level::INFO {
        return true;
    }
    !NOISY.iter().any(|n| is_crate(target, n))
}

/// Does `target` name this crate or a module inside it? (`monoio_http`,
/// `monoio_http::h2::codec` — but not `monoio_httpx`.)
fn is_crate(target: &str, krate: &str) -> bool {
    target.strip_prefix(krate).is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `log.level: debug` must give the router's own debug lines without the
    /// per-frame flood from monoio-http's h2 codec, which is what made debug
    /// unusable on a loaded server.
    #[test]
    fn debug_keeps_our_lines_and_drops_dependency_frames() {
        let ours = "sni_router::terminate";
        assert!(allow(ours, Level::DEBUG, Level::DEBUG));
        assert!(allow("access", Level::DEBUG, Level::DEBUG));
        assert!(!allow("monoio_http::h2::codec::framed_read", Level::DEBUG, Level::DEBUG));
        // Warnings and errors from dependencies always survive.
        assert!(allow("monoio_http::h2::codec::framed_read", Level::WARN, Level::DEBUG));
        // `trace` is the explicit "show me everything" escape hatch.
        assert!(allow("monoio_http::h2::codec::framed_read", Level::DEBUG, Level::TRACE));
        // Above the configured maximum nothing passes.
        assert!(!allow(ours, Level::DEBUG, Level::INFO));
    }

    /// Prefix matching must not swallow an unrelated crate that merely starts
    /// with the same letters.
    #[test]
    fn crate_match_is_not_a_bare_prefix() {
        assert!(is_crate("monoio", "monoio"));
        assert!(is_crate("monoio::net::tcp", "monoio"));
        assert!(!is_crate("monoio_rustls::stream", "monoio"));
        assert!(!allow("monoio_http::h2", Level::DEBUG, Level::DEBUG));
        assert!(allow("monoio_httpx::thing", Level::DEBUG, Level::DEBUG));
    }
}
