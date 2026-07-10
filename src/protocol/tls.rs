//! TLS ClientHello SNI extraction.
//!
//! Runs over an *accumulating* byte buffer, never assuming the ClientHello
//! arrived in one read. This is what makes it robust against DPI-bypass tools
//! (Zapret / GoodbyeDPI / byedpi) that split the ClientHello across TCP
//! segments and TLS records and send them out of order:
//!
//! - **TCP segment splitting / reordering** is undone by the kernel before we
//!   read — we get a clean, in-order stream, just possibly a few bytes at a
//!   time. We handle that by returning [`Sni::Incomplete`] and being called
//!   again with more bytes.
//! - **Fake packets** (bad TCP checksum / low TTL / bad seq) are dropped by
//!   the kernel and never reach us, so we only ever parse the real handshake.
//! - **TLS-record-layer fragmentation** (a ClientHello spread over several
//!   handshake records) is reassembled here explicitly.
//!
//! Everything is bounds-checked; the parser never panics on hostile input
//! (matters because the build sets `panic = "abort"`).

/// Result of an SNI extraction attempt over the current buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Sni {
    /// SNI hostname found.
    Found(String),
    /// A complete, valid ClientHello with no usable SNI — route via `*`.
    Absent,
    /// Not enough bytes yet; call again once more have arrived.
    Incomplete,
    /// First bytes are not a TLS handshake / ClientHello, or the message is
    /// malformed. The stream is not something we can SNI-route.
    NotClientHello,
}

const REC_HANDSHAKE: u8 = 22;
const HS_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const SNI_HOST_NAME: u8 = 0;

/// Extract the SNI from a (possibly partial) TLS record stream.
///
/// `max` caps how many reassembled handshake bytes we will hold before giving
/// up — a hard limit on memory per pending connection, independent of the
/// handshake timeout.
pub fn extract_sni(buf: &[u8], max: usize) -> Sni {
    match reassemble_handshake(buf, max) {
        Reassembly::Complete(hs) => parse_client_hello(&hs),
        Reassembly::Incomplete => Sni::Incomplete,
        Reassembly::NotHandshake => Sni::NotClientHello,
    }
}

enum Reassembly {
    Complete(Vec<u8>),
    Incomplete,
    NotHandshake,
}

/// Walk TLS records (content type 22) and concatenate their fragments into a
/// single handshake message, stopping once the message's declared length is
/// covered.
fn reassemble_handshake(buf: &[u8], max: usize) -> Reassembly {
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0;

    loop {
        // Do we already hold a complete handshake message?
        if let Some(total) = handshake_total_len(&hs) {
            // A ClientHello that *declares* itself larger than our cap is
            // rejected up front — no point buffering toward a size we'd refuse.
            if total > max {
                return Reassembly::NotHandshake;
            }
            if hs.len() >= total {
                hs.truncate(total);
                return Reassembly::Complete(hs);
            }
        }
        // Need another record. A TLS record header is 5 bytes.
        if pos + 5 > buf.len() {
            return if buf.is_empty() {
                Reassembly::Incomplete
            } else if buf[0] != REC_HANDSHAKE {
                Reassembly::NotHandshake
            } else {
                Reassembly::Incomplete
            };
        }
        if buf[pos] != REC_HANDSHAKE {
            return Reassembly::NotHandshake;
        }
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let body_start = pos + 5;
        let body_end = body_start + rec_len;
        if body_end > buf.len() {
            return Reassembly::Incomplete; // record itself is truncated
        }
        hs.extend_from_slice(&buf[body_start..body_end]);
        if hs.len() > max {
            return Reassembly::NotHandshake; // refuse to buffer unbounded input
        }
        pos = body_end;
    }
}

/// Total length (header + body) of the handshake message at the front of `hs`,
/// or `None` if we can't read the 4-byte header yet.
fn handshake_total_len(hs: &[u8]) -> Option<usize> {
    if hs.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    Some(4 + len)
}

/// Parse a reassembled handshake message and pull out the SNI.
///
/// Also used directly by the QUIC path, where CRYPTO frames carry the TLS
/// handshake message without any record layer.
pub fn parse_client_hello(hs: &[u8]) -> Sni {
    let mut c = Cursor::new(hs);
    match c.u8() {
        Some(HS_CLIENT_HELLO) => {}
        Some(_) => return Sni::NotClientHello,
        None => return Sni::Incomplete,
    }
    // 3-byte handshake length; if the buffer is shorter than promised we simply
    // haven't received the whole message yet.
    let body_len = match c.u24() {
        Some(n) => n as usize,
        None => return Sni::Incomplete,
    };
    let body = match c.take(body_len) {
        Some(b) => b,
        None => return Sni::Incomplete,
    };

    // Anything malformed *inside* a message that claims to be complete is a
    // hard reject, not "wait for more".
    parse_client_hello_body(body).unwrap_or(Sni::NotClientHello)
}

fn parse_client_hello_body(body: &[u8]) -> Option<Sni> {
    let mut c = Cursor::new(body);
    c.take(2)?; // client_version
    c.take(32)?; // random
    let sid_len = c.u8()? as usize;
    c.take(sid_len)?; // session_id
    let cs_len = c.u16()? as usize;
    c.take(cs_len)?; // cipher_suites
    let comp_len = c.u8()? as usize;
    c.take(comp_len)?; // compression_methods

    // Extensions are optional in the wire format (though universal in TLS 1.3).
    let ext_total = match c.u16() {
        Some(n) => n as usize,
        None => return Some(Sni::Absent),
    };
    let exts = c.take(ext_total)?;

    let mut ec = Cursor::new(exts);
    while ec.remaining() > 0 {
        let ext_type = ec.u16()?;
        let ext_len = ec.u16()? as usize;
        let ext_data = ec.take(ext_len)?;
        if ext_type == EXT_SERVER_NAME {
            return Some(parse_server_name(ext_data));
        }
    }
    Some(Sni::Absent)
}

fn parse_server_name(ext: &[u8]) -> Sni {
    // ServerNameList: 2-byte list length, then entries of {type(1), len(2), name}.
    let mut c = Cursor::new(ext);
    let list_len = match c.u16() {
        Some(n) => n as usize,
        None => return Sni::Absent, // empty server_name ext (seen in ServerHello, tolerate)
    };
    let list = match c.take(list_len) {
        Some(l) => l,
        None => return Sni::NotClientHello,
    };
    let mut lc = Cursor::new(list);
    while lc.remaining() > 0 {
        let name_type = match lc.u8() {
            Some(t) => t,
            None => break,
        };
        let name_len = match lc.u16() {
            Some(n) => n as usize,
            None => break,
        };
        let name = match lc.take(name_len) {
            Some(n) => n,
            None => break,
        };
        if name_type == SNI_HOST_NAME {
            // host_name is ASCII (IDNA/punycode is ASCII too). Reject non-UTF-8
            // rather than routing on garbage.
            return match std::str::from_utf8(name) {
                Ok(s) if !s.is_empty() => Sni::Found(s.to_ascii_lowercase()),
                _ => Sni::Absent,
            };
        }
    }
    Sni::Absent
}

/// Minimal bounds-checked byte reader — every read returns `None` instead of
/// panicking when the buffer is too short.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        self.take(3).map(|s| u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
}

#[cfg(test)]
pub(crate) mod build {
    //! ClientHello builders shared by the tls and quic tests.

    /// Build a ClientHello *handshake message* (msg_type + len + body), with an
    /// optional SNI extension. Not a full TLS record.
    pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session_id length 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2, TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: len 1, null

        let mut exts = Vec::new();
        if let Some(host) = sni {
            let host = host.as_bytes();
            let mut sn = Vec::new();
            sn.push(0u8); // host_name type
            sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sn.extend_from_slice(host);
            let mut ext_data = Vec::new();
            ext_data.extend_from_slice(&(sn.len() as u16).to_be_bytes()); // server_name_list len
            ext_data.extend_from_slice(&sn);
            exts.extend_from_slice(&0u16.to_be_bytes()); // ext type server_name
            exts.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&ext_data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(1); // ClientHello
        let len = body.len() as u32;
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Wrap a handshake message in one or more TLS handshake records, splitting
    /// the message every `chunk` bytes (0 = single record) to emulate TLS-record
    /// fragmentation.
    pub fn records(msg: &[u8], chunk: usize) -> Vec<u8> {
        let step = if chunk == 0 { msg.len().max(1) } else { chunk };
        let mut out = Vec::new();
        for part in msg.chunks(step) {
            out.push(22); // handshake
            out.extend_from_slice(&[0x03, 0x01]); // legacy record version
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use build::{client_hello, records};

    const MAX: usize = 16 * 1024;

    #[test]
    fn full_client_hello_with_sni() {
        let rec = records(&client_hello(Some("example.com")), 0);
        assert_eq!(extract_sni(&rec, MAX), Sni::Found("example.com".into()));
    }

    #[test]
    fn sni_is_lowercased() {
        let rec = records(&client_hello(Some("Example.COM")), 0);
        assert_eq!(extract_sni(&rec, MAX), Sni::Found("example.com".into()));
    }

    #[test]
    fn no_sni_extension_is_absent() {
        let rec = records(&client_hello(None), 0);
        assert_eq!(extract_sni(&rec, MAX), Sni::Absent);
    }

    #[test]
    fn fragmented_across_tls_records() {
        // ClientHello split into 3-byte TLS records — the reassembler must
        // stitch them back together.
        let rec = records(&client_hello(Some("split.example.com")), 3);
        assert!(rec.len() > 20, "expected several records");
        assert_eq!(extract_sni(&rec, MAX), Sni::Found("split.example.com".into()));
    }

    #[test]
    fn byte_by_byte_prefix_is_incomplete_then_found() {
        // Emulate a Zapret-style dribble: every prefix shorter than the whole
        // ClientHello must say Incomplete (never NotClientHello, never a panic),
        // and the full buffer must yield the SNI.
        let full = records(&client_hello(Some("dribble.example.com")), 4);
        for n in 1..full.len() {
            match extract_sni(&full[..n], MAX) {
                Sni::Incomplete | Sni::Found(_) => {}
                other => panic!("prefix len {n} gave {other:?}"),
            }
        }
        assert_eq!(extract_sni(&full, MAX), Sni::Found("dribble.example.com".into()));
    }

    #[test]
    fn non_tls_first_byte_is_rejected() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n", MAX), Sni::NotClientHello);
    }

    #[test]
    fn empty_buffer_is_incomplete() {
        assert_eq!(extract_sni(b"", MAX), Sni::Incomplete);
    }

    #[test]
    fn truncated_record_is_incomplete() {
        let rec = records(&client_hello(Some("example.com")), 0);
        assert_eq!(extract_sni(&rec[..rec.len() - 5], MAX), Sni::Incomplete);
    }

    #[test]
    fn oversize_handshake_is_rejected_not_buffered_forever() {
        // A record claiming to be a handshake but exceeding the cap must be
        // rejected rather than accumulated without bound.
        let mut rec = vec![22u8, 0x03, 0x01, 0x00, 0x08];
        rec.extend_from_slice(&[1, 0xff, 0xff, 0xff, 0, 0, 0, 0]); // huge declared len
        assert_eq!(extract_sni(&rec, 16), Sni::NotClientHello);
    }

    #[test]
    fn garbage_inside_complete_message_is_rejected() {
        // A ClientHello whose declared length is satisfied but whose inner
        // length fields are inconsistent must be rejected, not looped on.
        let mut msg = client_hello(Some("example.com"));
        // Corrupt the session_id length to point past the end.
        msg[38] = 0xff;
        let rec = records(&msg, 0);
        assert_eq!(extract_sni(&rec, MAX), Sni::NotClientHello);
    }
}
