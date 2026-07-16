//! `sni-router` internals, exposed as a library so the fuzz targets (and any
//! future integration tests) can reach the protocol parsers directly.
//!
//! The binary in `main.rs` is the only intended consumer besides `fuzz/`; this
//! is not a stable public API.

pub mod acl;
pub mod admin;
pub mod backend;
pub mod config;
pub mod logging;
pub mod metrics;
pub mod protocol;
pub mod redirect;
pub mod router;
pub mod server;
pub mod terminate;
pub mod update;
