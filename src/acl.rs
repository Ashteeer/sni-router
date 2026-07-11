//! Access control: per-listener allow/deny lists by client IP (CIDR) and by
//! SNI pattern. Compiled once at startup from [`crate::config::AclConfig`].
//!
//! Evaluation order (deny wins):
//! - if any deny entry matches -> reject;
//! - else if the allow list is non-empty and nothing matches -> reject;
//! - else -> allow.
//!
//! ponytail: hand-rolled CIDR (~40 lines) instead of the `ipnet` crate — a
//! prefix-bit compare is all we need and it keeps the dependency surface small.

use crate::config::AclConfig;
use crate::router;
use std::net::IpAddr;

/// A CIDR block (or a single address, prefix = full length).
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `"10.0.0.0/8"`, `"192.168.1.5"`, `"2001:db8::/32"` or `"::1"`.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (ip_part, prefix_part) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: IpAddr = ip_part
            .parse()
            .map_err(|_| format!("invalid IP address \"{ip_part}\""))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            None => max,
            Some(p) => {
                let n: u8 = p.parse().map_err(|_| format!("invalid prefix length \"{p}\""))?;
                if n > max {
                    return Err(format!("prefix /{n} out of range for this address (max /{max})"));
                }
                n
            }
        };
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false, // different families never match
        }
    }
}

/// Compare the first `prefix` bits of two equal-length byte arrays.
fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Compiled access control for one listener.
#[derive(Debug, Default)]
pub struct Acl {
    allow_ip: Vec<Cidr>,
    deny_ip: Vec<Cidr>,
    allow_sni: Vec<String>,
    deny_sni: Vec<String>,
}

impl Acl {
    /// Compile from config, parsing every CIDR. Assumes the config already
    /// passed validation (returns an error only if a CIDR is malformed).
    pub fn compile(c: &AclConfig) -> Result<Acl, String> {
        let cidrs = |v: &[String]| v.iter().map(|s| Cidr::parse(s)).collect::<Result<Vec<_>, _>>();
        Ok(Acl {
            allow_ip: cidrs(&c.allow_ip)?,
            deny_ip: cidrs(&c.deny_ip)?,
            allow_sni: c.allow_sni.clone(),
            deny_sni: c.deny_sni.clone(),
        })
    }

    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        if self.deny_ip.iter().any(|c| c.contains(ip)) {
            return false;
        }
        self.allow_ip.is_empty() || self.allow_ip.iter().any(|c| c.contains(ip))
    }

    /// Check an SNI (may be `""` for a connection without one). Uses the same
    /// wildcard semantics as routing.
    pub fn sni_allowed(&self, sni: &str) -> bool {
        if self.deny_sni.iter().any(|p| router::matches(p, sni)) {
            return false;
        }
        self.allow_sni.is_empty() || self.allow_sni.iter().any(|p| router::matches(p, sni))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4_membership() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("11.0.0.1")));
    }

    #[test]
    fn cidr_odd_prefix() {
        let c = Cidr::parse("192.168.1.0/23").unwrap();
        assert!(c.contains(ip("192.168.1.5")));
        assert!(c.contains(ip("192.168.0.5")));
        assert!(!c.contains(ip("192.168.2.5")));
    }

    #[test]
    fn single_host_and_v6() {
        assert!(Cidr::parse("192.168.1.5").unwrap().contains(ip("192.168.1.5")));
        assert!(!Cidr::parse("192.168.1.5").unwrap().contains(ip("192.168.1.6")));
        assert!(Cidr::parse("2001:db8::/32").unwrap().contains(ip("2001:db8:1::1")));
        assert!(!Cidr::parse("2001:db8::/32").unwrap().contains(ip("2001:db9::1")));
    }

    #[test]
    fn bad_cidr_rejected() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
    }

    fn acl(allow_ip: &[&str], deny_ip: &[&str], allow_sni: &[&str], deny_sni: &[&str]) -> Acl {
        Acl::compile(&AclConfig {
            allow_ip: allow_ip.iter().map(|s| s.to_string()).collect(),
            deny_ip: deny_ip.iter().map(|s| s.to_string()).collect(),
            allow_sni: allow_sni.iter().map(|s| s.to_string()).collect(),
            deny_sni: deny_sni.iter().map(|s| s.to_string()).collect(),
        })
        .unwrap()
    }

    #[test]
    fn deny_beats_allow() {
        let a = acl(&["10.0.0.0/8"], &["10.0.0.66"], &[], &[]);
        assert!(a.ip_allowed(ip("10.1.1.1")));
        assert!(!a.ip_allowed(ip("10.0.0.66"))); // denied despite being in allow range
        assert!(!a.ip_allowed(ip("8.8.8.8"))); // not in allow list
    }

    #[test]
    fn empty_acl_allows_all() {
        let a = acl(&[], &[], &[], &[]);
        assert!(a.ip_allowed(ip("1.2.3.4")));
        assert!(a.sni_allowed("anything.com"));
        assert!(a.sni_allowed(""));
    }

    #[test]
    fn sni_allow_and_deny() {
        let a = acl(&[], &[], &["*.example.com"], &["bad.example.com"]);
        assert!(a.sni_allowed("good.example.com"));
        assert!(!a.sni_allowed("bad.example.com"));
        assert!(!a.sni_allowed("other.org"));
    }
}
