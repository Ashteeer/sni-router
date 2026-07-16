//! Fuzz the TLS ClientHello parser with arbitrary bytes.
//!
//! This parser is the router's front door: it reads attacker-controlled bytes
//! from any anonymous client before routing. The binary ships `panic = "abort"`,
//! so any panic here — a slice out of range, an arithmetic overflow — is a
//! remote crash, which is what this target hunts for. It must only ever return
//! `Sni::{Found, None, Incomplete}`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sni_router::protocol::tls;

fuzz_target!(|data: &[u8]| {
    // 16 KiB is the shipped default for limits.max_client_hello.
    let _ = tls::extract_sni(data, 16 * 1024);
    // Also drive the handshake-body parser directly, so the fuzzer isn't forced
    // to rediscover valid record framing before it can reach the interesting
    // extension-parsing code.
    let _ = tls::parse_client_hello(data);
});
