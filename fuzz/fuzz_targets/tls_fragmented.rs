//! Fuzz the *incremental* ClientHello path — the one Zapret-style clients
//! exercise by splitting the handshake across TCP segments.
//!
//! `server.rs` calls `extract_sni` again on every read, over a growing buffer,
//! and only stops when the answer is no longer `Incomplete`. A parser can be
//! panic-free on whole inputs yet still fault on a prefix that ends mid-length
//! or mid-extension, so this target replays that loop: the first byte picks the
//! chunk size, the rest is fed a chunk at a time.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sni_router::protocol::tls;

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else { return };
    let chunk = (chunk as usize).max(1);
    let mut buf: Vec<u8> = Vec::new();
    for piece in rest.chunks(chunk) {
        buf.extend_from_slice(piece);
        if !matches!(tls::extract_sni(&buf, 16 * 1024), tls::Sni::Incomplete) {
            break; // routed (or rejected) — the server stops reading here too
        }
    }
});
