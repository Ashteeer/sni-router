//! Fuzz the QUIC Initial parser: header parsing, header protection removal and
//! AEAD decryption, then SNI extraction from the CRYPTO frames.
//!
//! Same threat model as the TLS target — arbitrary UDP datagrams from anyone —
//! but more machinery behind it (variable-length integers, packet-number
//! recovery, per-version key schedules), so more places to get an index wrong.
//! Garbage must come back as `Scan::Fake`/`Scan::NotQuic`, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sni_router::protocol::quic;

fuzz_target!(|data: &[u8]| {
    let _ = quic::scan(data);

    // The reassembler, driven directly: a ClientHello can arrive spread over
    // several Initials, and CRYPTO offsets are attacker-chosen. Feeding a wild
    // offset must not panic or try to allocate its way to it.
    if let Some((off, rest)) = data.split_at_checked(8) {
        let offset = u64::from_le_bytes(off.try_into().expect("8 bytes"));
        let mut reasm = quic::CryptoReasm::new();
        reasm.push(offset, rest);
        let _ = reasm.try_sni();
    }
});
