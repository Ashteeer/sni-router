//! PROXY protocol v1/v2 header encoder.
//!
//! In passthrough mode there are no HTTP headers to carry the client's real
//! IP, so we prepend a PROXY protocol header to the backend connection. This
//! is encode-only: sni-router is the sender, backends are the receivers.
//!
//! `src` is the real client address; `dst` is the address the client connected
//! to on the router (what the backend would otherwise see as the peer). v2 can
//! carry IPv6 client info even when the backend link is IPv4 — the two sides of
//! the header are independent.

use std::net::SocketAddr;

const V2_SIG: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// PROXY protocol v1 (human-readable, TCP only).
///
/// Falls back to `PROXY UNKNOWN` if the two addresses are different families
/// (which shouldn't happen for a single accepted connection).
pub fn v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            s.ip(), d.ip(), s.port(), d.port()
        )
        .into_bytes(),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            s.ip(), d.ip(), s.port(), d.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

/// PROXY protocol v2 (binary). `dgram = true` marks the transport as DGRAM
/// (UDP/QUIC) instead of STREAM (TCP).
pub fn v2(src: SocketAddr, dst: SocketAddr, dgram: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&V2_SIG);
    out.push(0x21); // version 2 (0x2_) + PROXY command (0x_1)

    // transport protocol nibble: 1 = STREAM, 2 = DGRAM
    let tp = if dgram { 0x2 } else { 0x1 };
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            out.push(0x10 | tp); // AF_INET
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            out.push(0x20 | tp); // AF_INET6
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        // Mixed families on a single connection: emit LOCAL/UNSPEC so the
        // backend ignores the address block rather than getting a bogus one.
        _ => {
            out.push(0x00); // AF_UNSPEC + UNSPEC
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_tcp4() {
        let src = "203.0.113.7:56324".parse().unwrap();
        let dst = "198.51.100.1:443".parse().unwrap();
        assert_eq!(v1(src, dst), b"PROXY TCP4 203.0.113.7 198.51.100.1 56324 443\r\n");
    }

    #[test]
    fn v1_tcp6() {
        let src = "[2001:db8::1]:56324".parse().unwrap();
        let dst = "[2001:db8::2]:443".parse().unwrap();
        assert_eq!(v1(src, dst), b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n");
    }

    #[test]
    fn v2_tcp4_layout() {
        let src: SocketAddr = "203.0.113.7:56324".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let h = v2(src, dst, false);
        assert_eq!(&h[..12], &V2_SIG);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11); // AF_INET + STREAM
        assert_eq!(&h[14..16], &12u16.to_be_bytes());
        assert_eq!(&h[16..20], &[203, 0, 113, 7]);
        assert_eq!(&h[20..24], &[198, 51, 100, 1]);
        assert_eq!(&h[24..26], &56324u16.to_be_bytes());
        assert_eq!(&h[26..28], &443u16.to_be_bytes());
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn v2_udp_sets_dgram_nibble() {
        let src: SocketAddr = "203.0.113.7:1".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:2".parse().unwrap();
        assert_eq!(v2(src, dst, true)[13], 0x12); // AF_INET + DGRAM
    }

    #[test]
    fn v2_tcp6_len() {
        let src: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:2".parse().unwrap();
        let h = v2(src, dst, false);
        assert_eq!(h[13], 0x21); // AF_INET6 + STREAM
        assert_eq!(&h[14..16], &36u16.to_be_bytes());
        assert_eq!(h.len(), 16 + 36);
    }
}
