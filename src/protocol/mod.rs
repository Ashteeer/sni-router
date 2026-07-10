//! Wire-format parsers for untrusted client input — the security-critical core.
//!
//! Every parser here is fed ClientHello / QUIC Initial bytes from anonymous
//! clients, so all of it is bounds-checked and panic-free (the release build
//! runs with `panic = "abort"`).

pub mod proxy_protocol;
pub mod quic;
pub mod tls;
