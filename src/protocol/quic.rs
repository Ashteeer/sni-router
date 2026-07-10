//! QUIC Initial packet SNI extraction (RFC 9000 / RFC 9001, QUIC v1).
//!
//! The client's first flight carries the TLS ClientHello inside CRYPTO frames
//! in **Initial** packets. Those packets are encrypted, but with keys derived
//! from the (public) Destination Connection ID via a fixed salt — no server
//! private key is involved. We reproduce that key schedule, remove header
//! protection, AEAD-decrypt the payload, pull the CRYPTO frames out and hand
//! the reassembled ClientHello to [`crate::protocol::tls::parse_client_hello`].
//!
//! Robustness against DPI-bypass tools (Zapret QUIC modes) comes for free from
//! the crypto: a **fake Initial won't authenticate**, so AEAD failure is our
//! signal to ignore that datagram and wait for the real one ([`Scan::Fake`]).
//! Fragmentation / reordering of the ClientHello across several Initials is
//! handled by [`CryptoReasm`], which reassembles CRYPTO frames by offset.
//!
//! Only QUIC v1 (version 0x00000001) is decrypted; other versions (including
//! v2) return [`Scan::NotInitial`].
//! ponytail: v2 salt+labels are unverified constants — not shipping crypto I
//! can't pin to a test vector; add when a v2 vector is on hand.

use crate::protocol::tls::{self, Sni};
use std::collections::BTreeMap;

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 9001 §5.2 initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const VERSION_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Cap on reassembled CRYPTO bytes per flow — bounds memory when a hostile
/// client streams many small/overlapping fragments.
pub const MAX_CRYPTO: usize = 64 * 1024;

/// Outcome of scanning one datagram for Initial CRYPTO data.
#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    /// Decrypted CRYPTO fragments (offset, data). May be empty (all padding).
    Crypto(Vec<(u64, Vec<u8>)>),
    /// Leading packet is not a QUIC v1 Initial (short header, other version,
    /// too short) — not our concern.
    NotInitial,
    /// Looked like an Initial but failed to authenticate: a fake/garbage packet
    /// (e.g. Zapret QUIC fooling). Skip it and keep waiting.
    Fake,
}

/// Scan a UDP datagram, decrypting every leading coalesced Initial packet and
/// returning all CRYPTO fragments found.
pub fn scan(datagram: &[u8]) -> Scan {
    if !looks_like_initial_v1(datagram) {
        return Scan::NotInitial;
    }
    let mut frags = Vec::new();
    let mut off = 0;
    while looks_like_initial_v1(&datagram[off..]) {
        match decrypt_one(&datagram[off..]) {
            Ok((mut f, consumed)) => {
                frags.append(&mut f);
                if consumed == 0 {
                    break;
                }
                off += consumed;
            }
            // First packet failed => treat the whole datagram as a fake.
            // A later coalesced packet failing just ends the scan.
            Err(_) if off == 0 => return Scan::Fake,
            Err(_) => break,
        }
        if off >= datagram.len() {
            break;
        }
    }
    Scan::Crypto(frags)
}

/// Convenience single-datagram path (used by tests and the common case where
/// the whole ClientHello fits in one datagram).
pub fn extract_sni(datagram: &[u8]) -> Sni {
    match scan(datagram) {
        Scan::Crypto(frags) => {
            let mut r = CryptoReasm::new();
            for (off, data) in frags {
                r.push(off, &data);
            }
            r.try_sni()
        }
        Scan::Fake | Scan::NotInitial => Sni::NotClientHello,
    }
}

fn looks_like_initial_v1(pkt: &[u8]) -> bool {
    pkt.len() >= 5 && (pkt[0] & 0xF0) == 0xC0 && pkt[1..5] == VERSION_V1
}

enum DecErr {
    Truncated,
    Undecryptable,
}

/// Decrypt one Initial packet at the front of `pkt`. Returns the CRYPTO
/// fragments and how many bytes this packet consumed (for coalesced parsing).
fn decrypt_one(pkt: &[u8]) -> Result<(Vec<(u64, Vec<u8>)>, usize), DecErr> {
    let mut c = Cur::new(pkt);
    let byte0 = c.u8().ok_or(DecErr::Truncated)?;
    c.take(4).ok_or(DecErr::Truncated)?; // version (already checked v1)
    let dcid_len = c.u8().ok_or(DecErr::Truncated)? as usize;
    if dcid_len > 20 {
        return Err(DecErr::Undecryptable);
    }
    let dcid = c.take(dcid_len).ok_or(DecErr::Truncated)?.to_vec();
    let scid_len = c.u8().ok_or(DecErr::Truncated)? as usize;
    if scid_len > 20 {
        return Err(DecErr::Undecryptable);
    }
    c.take(scid_len).ok_or(DecErr::Truncated)?;
    let token_len = c.varint().ok_or(DecErr::Truncated)? as usize;
    c.take(token_len).ok_or(DecErr::Truncated)?;
    let length = c.varint().ok_or(DecErr::Truncated)? as usize;

    let pn_offset = c.pos;
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > pkt.len() {
        return Err(DecErr::Truncated);
    }
    // The Length field covers packet number + protected payload (incl. tag).
    let pkt_end = pn_offset + length;
    if pkt_end > pkt.len() || length < 4 + 16 {
        return Err(DecErr::Truncated);
    }

    let keys = Keys::derive(&dcid);

    // Remove header protection.
    let sample = &pkt[sample_offset..sample_offset + 16];
    let mask = keys.hp_mask(sample).ok_or(DecErr::Undecryptable)?;
    let byte0 = byte0 ^ (mask[0] & 0x0f); // long header: low 4 bits
    let pn_len = (byte0 & 0x03) as usize + 1;

    let mut pn_bytes = [0u8; 4];
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let b = pkt[pn_offset + i] ^ mask[1 + i];
        pn_bytes[i] = b;
        pn = (pn << 8) | b as u64;
    }

    // AAD = the reconstructed (unprotected) header up to end of packet number.
    let hdr_len = pn_offset + pn_len;
    let mut aad = pkt[..hdr_len].to_vec();
    aad[0] = byte0;
    aad[pn_offset..hdr_len].copy_from_slice(&pn_bytes[..pn_len]);

    let ct = &pkt[hdr_len..pkt_end];
    let plaintext = keys.open(pn, &aad, ct).ok_or(DecErr::Undecryptable)?;

    Ok((parse_crypto_frames(&plaintext), pkt_end))
}

/// Pull CRYPTO frames (offset, data) out of a decrypted Initial payload.
/// Skips PADDING/PING/ACK; stops at the first frame type it doesn't model
/// (client Initials only carry these).
fn parse_crypto_frames(payload: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut c = Cur::new(payload);
    while let Some(ty) = c.u8() {
        match ty {
            0x00 | 0x01 => {} // PADDING, PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range_count, first_range, ranges[..]
                if c.varint().is_none() || c.varint().is_none() {
                    break;
                }
                let ranges = match c.varint() {
                    Some(n) => n,
                    None => break,
                };
                if c.varint().is_none() {
                    break;
                }
                let mut ok = true;
                for _ in 0..ranges {
                    if c.varint().is_none() || c.varint().is_none() {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                if ty == 0x03 {
                    // ECN counts
                    if c.varint().is_none() || c.varint().is_none() || c.varint().is_none() {
                        break;
                    }
                }
            }
            0x06 => {
                // CRYPTO: offset, length, data
                let (offset, len) = match (c.varint(), c.varint()) {
                    (Some(o), Some(l)) => (o, l as usize),
                    _ => break,
                };
                match c.take(len) {
                    Some(data) => out.push((offset, data.to_vec())),
                    None => break,
                }
            }
            _ => break, // unknown frame: can't safely skip, stop here
        }
    }
    out
}

struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl Keys {
    fn derive(dcid: &[u8]) -> Self {
        let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);
        let cis = hkdf_expand_label(&initial_secret, b"client in", 32);
        let key = hkdf_expand_label(&cis, b"quic key", 16);
        let iv = hkdf_expand_label(&cis, b"quic iv", 12);
        let hp = hkdf_expand_label(&cis, b"quic hp", 16);
        let mut k = Keys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
        k.key.copy_from_slice(&key);
        k.iv.copy_from_slice(&iv);
        k.hp.copy_from_slice(&hp);
        k
    }

    /// AES-128-ECB one-block header-protection mask (first 5 bytes).
    fn hp_mask(&self, sample: &[u8]) -> Option<[u8; 5]> {
        let cipher = Aes128::new_from_slice(&self.hp).ok()?;
        let mut block = *aes::cipher::generic_array::GenericArray::from_slice(&sample[..16]);
        cipher.encrypt_block(&mut block);
        let mut m = [0u8; 5];
        m.copy_from_slice(&block[..5]);
        Some(m)
    }

    /// AES-128-GCM open with the QUIC nonce (iv XOR packet number).
    fn open(&self, pn: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = self.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b; // right-align the 8-byte pn into the 12-byte iv
        }
        let cipher = Aes128Gcm::new_from_slice(&self.key).ok()?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad })
            .ok()
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context, SHA-256.
fn hkdf_expand_label(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let full_label = [b"tls13 ".as_slice(), label].concat();
    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0); // empty context
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("PRK length is valid");
    let mut okm = vec![0u8; out_len];
    hk.expand(&info, &mut okm).expect("valid output length");
    okm
}

/// Reassembles CRYPTO-frame fragments (by offset) into the contiguous
/// ClientHello, across as many datagrams as it takes.
pub struct CryptoReasm {
    frags: BTreeMap<u64, Vec<u8>>,
    total: usize,
}

impl CryptoReasm {
    pub fn new() -> Self {
        Self { frags: BTreeMap::new(), total: 0 }
    }

    /// Add a fragment. Bounded by [`MAX_CRYPTO`]; over-cap fragments are dropped.
    pub fn push(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() || self.total.saturating_add(data.len()) > MAX_CRYPTO {
            return;
        }
        // Keep the longest fragment seen at a given offset (handles duplicates
        // from retransmits / fakes without unbounded growth).
        let replace = self.frags.get(&offset).map_or(true, |e| e.len() < data.len());
        if replace {
            if let Some(old) = self.frags.insert(offset, data.to_vec()) {
                self.total -= old.len();
            }
            self.total += data.len();
        }
    }

    /// Contiguous bytes starting at offset 0 (stops at the first gap).
    fn contiguous(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut next = 0u64;
        for (&off, data) in &self.frags {
            if off > next {
                break; // gap
            }
            // Fragment may overlap what we already have.
            let skip = (next - off) as usize;
            if skip < data.len() {
                buf.extend_from_slice(&data[skip..]);
                next += (data.len() - skip) as u64;
            }
        }
        buf
    }

    pub fn try_sni(&self) -> Sni {
        tls::parse_client_hello(&self.contiguous())
    }
}

impl Default for CryptoReasm {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounds-checked cursor with QUIC varint support.
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
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
    /// QUIC variable-length integer (RFC 9000 §16).
    fn varint(&mut self) -> Option<u64> {
        let first = *self.b.get(self.pos)?;
        let len = 1usize << (first >> 6); // 1, 2, 4 or 8 bytes
        let bytes = self.take(len)?;
        let mut v = (bytes[0] & 0x3f) as u64;
        for &b in &bytes[1..] {
            v = (v << 8) | b as u64;
        }
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tls::build::client_hello;

    // Ground-truth from RFC 9001 Appendix A.1 (DCID 0x8394c8f03e515708).
    const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn key_schedule_matches_rfc9001() {
        let keys = Keys::derive(&RFC_DCID);
        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn header_protection_mask_matches_rfc9001() {
        let keys = Keys::derive(&RFC_DCID);
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        assert_eq!(keys.hp_mask(&sample).unwrap().to_vec(), hex("437b9aec36"));
    }

    /// Build a QUIC v1 Initial carrying `frames` as its payload, sealed with the
    /// same key schedule the parser uses (inverse of `decrypt_one`).
    fn seal_initial(dcid: &[u8], pn: u64, mut frames: Vec<u8>) -> Vec<u8> {
        let pn_len = 4usize;
        // Ensure the payload is long enough for a 16-byte header-protection
        // sample taken 4 bytes past the packet number.
        while frames.len() < 4 + 16 {
            frames.push(0); // PADDING
        }
        let keys = Keys::derive(dcid);

        let mut nonce = keys.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }

        // Unprotected header.
        let mut hdr = Vec::new();
        hdr.push(0xC0 | (pn_len as u8 - 1)); // long + fixed + Initial + pn_len
        hdr.extend_from_slice(&VERSION_V1);
        hdr.push(dcid.len() as u8);
        hdr.extend_from_slice(dcid);
        hdr.push(0); // scid len
        hdr.push(0x00); // token length varint = 0
        let length = pn_len + frames.len() + 16;
        // 2-byte varint length (0b01 prefix).
        hdr.extend_from_slice(&[0x40 | (length >> 8) as u8, length as u8]);
        let pn_offset = hdr.len();
        hdr.extend_from_slice(&(pn as u32).to_be_bytes()); // 4-byte pn

        let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &frames, aad: &hdr })
            .unwrap();

        let mut pkt = hdr.clone();
        pkt.extend_from_slice(&ct);

        // Apply header protection.
        let sample = &pkt[pn_offset + 4..pn_offset + 4 + 16];
        let mask = keys.hp_mask(sample).unwrap();
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
        pkt
    }

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        // 2-byte varints for offset and length (fits our test sizes).
        f.extend_from_slice(&[0x40 | (offset >> 8) as u8, offset as u8]);
        f.extend_from_slice(&[0x40 | (data.len() >> 8) as u8, data.len() as u8]);
        f.extend_from_slice(data);
        f
    }

    #[test]
    fn roundtrip_single_datagram() {
        let ch = client_hello(Some("quic.example.com"));
        let pkt = seal_initial(&RFC_DCID, 1, crypto_frame(0, &ch));
        assert_eq!(extract_sni(&pkt), Sni::Found("quic.example.com".into()));
    }

    #[test]
    fn fake_initial_is_rejected() {
        let ch = client_hello(Some("quic.example.com"));
        let mut pkt = seal_initial(&RFC_DCID, 1, crypto_frame(0, &ch));
        *pkt.last_mut().unwrap() ^= 0xff; // corrupt the auth tag
        assert_eq!(scan(&pkt), Scan::Fake);
    }

    #[test]
    fn short_header_is_not_initial() {
        assert_eq!(scan(&[0x40, 1, 2, 3, 4, 5, 6, 7, 8]), Scan::NotInitial);
    }

    #[test]
    fn fragmented_client_hello_across_two_frames() {
        // Split the ClientHello into two CRYPTO frames inside one Initial.
        let ch = client_hello(Some("frag.example.com"));
        let mid = ch.len() / 2;
        let mut frames = crypto_frame(0, &ch[..mid]);
        frames.extend(crypto_frame(mid as u64, &ch[mid..]));
        let pkt = seal_initial(&RFC_DCID, 1, frames);
        assert_eq!(extract_sni(&pkt), Sni::Found("frag.example.com".into()));
    }

    #[test]
    fn reassembly_across_datagrams_out_of_order() {
        // Two datagrams, second half arriving first — models Zapret reordering.
        let ch = client_hello(Some("split.example.com"));
        let mid = ch.len() / 2;
        let d1 = seal_initial(&RFC_DCID, 1, crypto_frame(0, &ch[..mid]));
        let d2 = seal_initial(&RFC_DCID, 2, crypto_frame(mid as u64, &ch[mid..]));

        let mut r = CryptoReasm::new();
        for d in [&d2, &d1] {
            if let Scan::Crypto(frags) = scan(d) {
                for (off, data) in frags {
                    r.push(off, &data);
                }
            }
        }
        assert_eq!(r.try_sni(), Sni::Found("split.example.com".into()));
    }
}
