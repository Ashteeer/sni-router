//! Static config validation (`--test-config` / `-t`).
//!
//! Collects *all* problems in one pass (compiler-style, not fail-fast) so the
//! user can fix everything in one edit. The exact same function must be used
//! by the SIGHUP reload path: an invalid new config is rejected and the old
//! one keeps running.

use super::{Config, HttpAction, Mode, Proto};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug)]
pub struct Diagnostic {
    pub level: Level,
    /// Config path, compiler-diagnostic style: `listeners[0].bind[1]`.
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self { level: Level::Error, path: path.into(), message: message.into() }
    }
    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self { level: Level::Warning, path: path.into(), message: message.into() }
    }
}

/// Run every static check. No network side effects (that's `--check-backends`,
/// implemented separately and opt-in).
pub fn validate(cfg: &Config) -> Vec<Diagnostic> {
    let mut d = Vec::new();

    if cfg.listeners.is_empty() {
        d.push(Diagnostic::error("listeners", "at least one listener is required"));
    }
    if cfg.backends.is_empty() {
        d.push(Diagnostic::error("backends", "at least one backend is required"));
    }

    // Duplicate listener names.
    for (i, l) in cfg.listeners.iter().enumerate() {
        if let Some(j) = cfg.listeners[..i].iter().position(|p| p.name == l.name) {
            d.push(Diagnostic::error(
                format!("listeners[{i}].name"),
                format!("duplicate listener name \"{}\" (already used by listeners[{j}])", l.name),
            ));
        }
    }

    // Bind addresses: syntax + duplicates. The same IP:port on tcp and udp is
    // fine (independent sockets) — the key is (proto, addr).
    let mut seen_binds: Vec<(Proto, SocketAddr, String)> = Vec::new();
    for (i, l) in cfg.listeners.iter().enumerate() {
        if l.bind.is_empty() {
            d.push(Diagnostic::error(
                format!("listeners[{i}].bind"),
                "at least one bind address is required",
            ));
        }
        for (k, b) in l.bind.iter().enumerate() {
            let path = format!("listeners[{i}].bind[{k}]");
            match b.parse::<SocketAddr>() {
                Ok(addr) => {
                    if let Some((_, _, prev)) =
                        seen_binds.iter().find(|(p, a, _)| *p == l.proto && *a == addr)
                    {
                        d.push(Diagnostic::error(
                            path,
                            format!("duplicate bind address \"{b}\" (already bound at {prev})"),
                        ));
                    } else {
                        seen_binds.push((l.proto, addr, path));
                    }
                }
                Err(_) => d.push(Diagnostic::error(
                    path,
                    format!(
                        "invalid address \"{b}\" — expected IP:port, \
                         e.g. \"0.0.0.0:443\" or \"[::]:443\""
                    ),
                )),
            }
        }
    }

    // Routes: referential integrity, udp+terminate, shadowing.
    for (i, l) in cfg.listeners.iter().enumerate() {
        if l.routes.is_empty() {
            d.push(Diagnostic::warning(
                format!("listeners[{i}].routes"),
                "listener has no routes — every connection will be dropped",
            ));
        }
        if let Some(acl) = &l.acl {
            for (field, list) in [("allow_ip", &acl.allow_ip), ("deny_ip", &acl.deny_ip)] {
                for (k, entry) in list.iter().enumerate() {
                    if let Err(e) = crate::acl::Cidr::parse(entry) {
                        d.push(Diagnostic::error(
                            format!("listeners[{i}].acl.{field}[{k}]"),
                            e,
                        ));
                    }
                }
            }
        }
        for (r, route) in l.routes.iter().enumerate() {
            let rp = format!("listeners[{i}].routes[{r}]");
            if route.sni.is_empty() {
                d.push(Diagnostic::error(format!("{rp}.sni"), "sni must not be empty"));
            }
            match cfg.backends.get(&route.backend) {
                None => {
                    let mut msg =
                        format!("\"{}\" references unknown backend", route.backend);
                    if let Some(s) = suggest(&route.backend, cfg.backends.keys()) {
                        msg.push_str(&format!(" (did you mean \"{s}\"?)"));
                    }
                    d.push(Diagnostic::error(format!("{rp}.backend"), msg));
                }
                Some(b) => {
                    // QUIC termination is post-MVP: udp listeners require
                    // passthrough backends.
                    if l.proto == Proto::Udp && b.mode != Mode::Passthrough {
                        d.push(Diagnostic::error(
                            format!("{rp}.backend"),
                            format!(
                                "backend \"{}\" has mode \"{}\", which is not \
                                 supported for udp (QUIC) listeners — use a \
                                 passthrough backend",
                                route.backend,
                                mode_name(b.mode)
                            ),
                        ));
                    }
                }
            }
            for (e, earlier) in l.routes[..r].iter().enumerate() {
                if covers(&earlier.sni, &route.sni) {
                    d.push(Diagnostic::warning(
                        rp.clone(),
                        format!(
                            "(sni: \"{}\") is unreachable — shadowed by earlier \
                             route[{e}] (sni: \"{}\")",
                            route.sni, earlier.sni
                        ),
                    ));
                    break;
                }
            }
        }
    }

    // Backends.
    for (name, b) in &cfg.backends {
        let bp = format!("backends.{name}");
        // Empty servers is only valid for redirect_https (no upstream).
        if b.servers.is_empty() && b.mode != Mode::RedirectHttps {
            d.push(Diagnostic::error(
                format!("{bp}.servers"),
                "at least one server is required",
            ));
        }
        for (k, s) in b.servers.iter().enumerate() {
            if s.parse::<SocketAddr>().is_err() {
                let msg = if s.parse::<IpAddr>().is_ok() {
                    format!("\"{s}\" — missing port")
                } else {
                    format!(
                        "invalid address \"{s}\" — expected IP:port \
                         (hostnames are not supported yet)"
                    )
                };
                d.push(Diagnostic::error(format!("{bp}.servers[{k}]"), msg));
            }
        }
        match b.mode {
            Mode::Terminate | Mode::TerminateTcp => {
                // Both terminate modes present a TLS cert to clients.
                match &b.tls {
                    None => d.push(Diagnostic::error(
                        format!("{bp}.tls"),
                        format!(
                            "mode \"{}\" requires a tls section with cert and key",
                            mode_name(b.mode)
                        ),
                    )),
                    Some(t) => {
                        for (field, p) in [("cert", &t.cert), ("key", &t.key)] {
                            if let Err(e) = std::fs::File::open(p) {
                                d.push(Diagnostic::error(
                                    format!("{bp}.tls.{field}"),
                                    format!("cannot read \"{}\": {e}", p.display()),
                                ));
                            }
                        }
                    }
                }
                if b.mode == Mode::Terminate {
                    if let Some(bt) = &b.backend_tls {
                        for (field, p) in [
                            ("ca", &bt.ca),
                            ("client_cert", &bt.client_cert),
                            ("client_key", &bt.client_key),
                        ] {
                            if let Some(path) = p {
                                if let Err(e) = std::fs::File::open(path) {
                                    d.push(Diagnostic::error(
                                        format!("{bp}.backend_tls.{field}"),
                                        format!("cannot read \"{}\": {e}", path.display()),
                                    ));
                                }
                            }
                        }
                        if bt.client_cert.is_some() != bt.client_key.is_some() {
                            d.push(Diagnostic::error(
                                format!("{bp}.backend_tls"),
                                "mTLS requires both client_cert and client_key (or neither)",
                            ));
                        }
                    }
                } else {
                    // terminate_tcp is a raw byte tunnel: HTTP-only knobs are ignored.
                    if b.backend_tls.is_some() {
                        d.push(Diagnostic::warning(
                            format!("{bp}.backend_tls"),
                            "backend_tls is ignored in terminate_tcp (raw) mode",
                        ));
                    }
                    if b.headers.any() {
                        d.push(Diagnostic::warning(
                            format!("{bp}.headers"),
                            "headers are ignored in terminate_tcp (raw) mode",
                        ));
                    }
                    if !b.http_rules.is_empty() {
                        d.push(Diagnostic::warning(
                            format!("{bp}.http_rules"),
                            "http_rules are ignored in terminate_tcp (raw) mode",
                        ));
                    }
                }
            }
            Mode::Passthrough => {
                if b.tls.is_some() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.tls"),
                        "tls section is ignored in passthrough mode",
                    ));
                }
                if b.backend_tls.is_some() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.backend_tls"),
                        "backend_tls is ignored in passthrough mode",
                    ));
                }
                if b.headers.any() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.headers"),
                        "headers are only applied in terminate mode",
                    ));
                }
                if !b.http_rules.is_empty() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.http_rules"),
                        "http_rules are only applied in terminate mode",
                    ));
                }
            }
            Mode::RedirectHttps => {
                if !b.servers.is_empty() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.servers"),
                        "servers are ignored in redirect_https mode (it sends a 301, no upstream)",
                    ));
                }
                if b.tls.is_some() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.tls"),
                        "tls is ignored in redirect_https mode (it serves plaintext :80)",
                    ));
                }
                if !b.http_rules.is_empty() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.http_rules"),
                        "http_rules are only applied in terminate mode",
                    ));
                }
            }
        }
        // Validate http_rules content (applicability is warned per-mode above).
        for (k, r) in b.http_rules.iter().enumerate() {
            let rpth = format!("{bp}.http_rules[{k}]");
            if r.path.is_empty() {
                d.push(Diagnostic::error(
                    format!("{rpth}.path"),
                    "path must not be empty (use \"*\" for catch-all)",
                ));
            }
            match r.action {
                HttpAction::Respond => match r.status {
                    None => d.push(Diagnostic::error(
                        format!("{rpth}.status"),
                        "action \"respond\" requires a status code",
                    )),
                    Some(s) if !(100..600).contains(&s) => d.push(Diagnostic::error(
                        format!("{rpth}.status"),
                        format!("status {s} out of range (100-599)"),
                    )),
                    _ => {}
                },
                HttpAction::Forward => {
                    if r.status.is_some() {
                        d.push(Diagnostic::warning(
                            format!("{rpth}.status"),
                            "status is ignored for action \"forward\"",
                        ));
                    }
                }
            }
        }
        let used = cfg
            .listeners
            .iter()
            .any(|l| l.routes.iter().any(|r| r.backend == *name));
        if !used {
            d.push(Diagnostic::warning(
                bp,
                format!("backend \"{name}\" is not referenced by any route"),
            ));
        }
    }

    // Timeouts: positive, sane.
    for (field, v) in [
        ("handshake", cfg.timeouts.handshake),
        ("connect", cfg.timeouts.connect),
        ("idle", cfg.timeouts.idle),
        ("health_interval", cfg.timeouts.health_interval),
        ("drain", cfg.timeouts.drain),
    ] {
        let p = format!("timeouts.{field}");
        if v == 0 {
            d.push(Diagnostic::error(p, "timeout must be greater than 0 (seconds)"));
        } else if v > 86_400 {
            d.push(Diagnostic::warning(p, format!("{v}s is unusually large (more than 24h)")));
        }
    }

    // Admin API bind address.
    if let Some(admin) = &cfg.admin {
        if admin.bind.parse::<SocketAddr>().is_err() {
            d.push(Diagnostic::error(
                "admin.bind",
                format!("invalid address \"{}\" — expected IP:port", admin.bind),
            ));
        }
    }

    // Metrics exporter bind address.
    if let Some(m) = &cfg.metrics {
        if m.bind.parse::<SocketAddr>().is_err() {
            d.push(Diagnostic::error(
                "metrics.bind",
                format!("invalid address \"{}\" — expected IP:port", m.bind),
            ));
        }
    }

    // Log level word.
    if crate::logging::parse_level(&cfg.log.level).is_none() {
        d.push(Diagnostic::error(
            "log.level",
            format!(
                "unknown level \"{}\" — expected one of error, warn, info, debug, trace",
                cfg.log.level
            ),
        ));
    }

    // Limits.
    if cfg.limits.max_client_hello < 512 {
        d.push(Diagnostic::error(
            "limits.max_client_hello",
            "must be at least 512 bytes (a real ClientHello does not fit in less)",
        ));
    } else if cfg.limits.max_client_hello > 1 << 20 {
        d.push(Diagnostic::warning(
            "limits.max_client_hello",
            "larger than 1 MiB — a ClientHello is normally a few KiB",
        ));
    }

    d
}

/// Human-readable mode name for diagnostics (matches the YAML spelling).
fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Passthrough => "passthrough",
        Mode::Terminate => "terminate",
        Mode::TerminateTcp => "terminate_tcp",
        Mode::RedirectHttps => "redirect_https",
    }
}

/// Does pattern `a` cover everything pattern `b` could match?
/// Wildcard semantics: `*` matches anything; `*.example.com` matches any
/// subdomain depth (suffix match) but not the apex `example.com` itself.
/// The runtime SNI matcher must agree with this function.
fn covers(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a == "*" {
        return true;
    }
    if let Some(sfx) = a.strip_prefix('*') {
        // a = "*.example.com", sfx = ".example.com"
        return match b.strip_prefix('*') {
            Some(bsfx) => bsfx.ends_with(sfx), // wildcard vs wildcard
            None => b.ends_with(sfx),          // wildcard vs exact
        };
    }
    false
}

/// Fuzzy-match an unknown backend name against existing ones (cargo-style
/// "did you mean" suggestions).
fn suggest<'a>(name: &str, candidates: impl Iterator<Item = &'a String>) -> Option<&'a str> {
    let best = candidates
        .map(|c| (levenshtein(name, c), c))
        .min_by_key(|(dist, _)| *dist)?;
    let (dist, c) = best;
    let max_len = name.len().max(c.len());
    (dist > 0 && dist * 3 <= max_len).then(|| c.as_str())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = Vec::with_capacity(b.len() + 1);
        cur.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg(yaml: &str) -> Config {
        serde_norway::from_str(yaml).expect("test yaml must parse")
    }

    fn errors(d: &[Diagnostic]) -> Vec<&Diagnostic> {
        d.iter().filter(|x| x.level == Level::Error).collect()
    }

    fn warnings(d: &[Diagnostic]) -> Vec<&Diagnostic> {
        d.iter().filter(|x| x.level == Level::Warning).collect()
    }

    const VALID: &str = r#"
listeners:
  - name: main
    bind: ["0.0.0.0:443", "[::]:443"]
    proto: tcp
    routes:
      - { sni: "example.com", backend: web }
      - { sni: "*.example.com", backend: web }
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#;

    #[test]
    fn valid_config_passes() {
        let d = validate(&cfg(VALID));
        assert!(d.is_empty(), "unexpected diagnostics: {d:?}");
    }

    #[test]
    fn unknown_backend_gets_suggestion() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes:
      - { sni: "*", backend: api_serv }
backends:
  api_servers:
    servers: ["10.0.0.1:443"]
"#));
        let e = errors(&d);
        assert_eq!(e.len(), 1, "{d:?}");
        assert!(e[0].message.contains("did you mean \"api_servers\""), "{}", e[0].message);
    }

    #[test]
    fn duplicate_bind_same_proto_is_error() {
        let d = validate(&cfg(r#"
listeners:
  - name: a
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: web }]
  - name: b
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: web }]
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        assert!(errors(&d).iter().any(|e| e.message.contains("duplicate bind")), "{d:?}");
    }

    #[test]
    fn same_addr_tcp_and_udp_is_ok() {
        let d = validate(&cfg(r#"
listeners:
  - name: tls
    bind: ["0.0.0.0:443"]
    proto: tcp
    routes: [{ sni: "*", backend: web }]
  - name: quic
    bind: ["0.0.0.0:443"]
    proto: udp
    routes: [{ sni: "*", backend: web }]
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        assert!(errors(&d).is_empty(), "{d:?}");
    }

    #[test]
    fn catch_all_shadows_later_routes() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes:
      - { sni: "*", backend: web }
      - { sni: "example.com", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        let w = warnings(&d);
        assert_eq!(w.len(), 1, "{d:?}");
        assert!(w[0].message.contains("unreachable"), "{}", w[0].message);
    }

    #[test]
    fn wildcard_shadows_matching_exact() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes:
      - { sni: "*.example.com", backend: web }
      - { sni: "foo.example.com", backend: web }
      - { sni: "example.com", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        // foo.example.com is shadowed; the apex example.com is NOT.
        let w = warnings(&d);
        assert_eq!(w.len(), 1, "{d:?}");
        assert!(w[0].path.contains("routes[1]"), "{}", w[0].path);
    }

    #[test]
    fn invalid_bind_address_is_error() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["300.0.0.1:443"]
    routes: [{ sni: "*", backend: web }]
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        assert!(errors(&d).iter().any(|e| e.message.contains("invalid address")), "{d:?}");
    }

    #[test]
    fn server_missing_port_is_error() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: web }]
backends:
  web:
    servers: ["10.0.0.1"]
"#));
        assert!(errors(&d).iter().any(|e| e.message.contains("missing port")), "{d:?}");
    }

    #[test]
    fn terminate_requires_tls() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: api }]
backends:
  api:
    mode: terminate
    servers: ["10.0.0.1:8080"]
"#));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("requires a tls section")),
            "{d:?}"
        );
    }

    #[test]
    fn udp_listener_rejects_terminate_backend() {
        let d = validate(&cfg(r#"
listeners:
  - name: q
    bind: ["0.0.0.0:8443"]
    proto: udp
    routes: [{ sni: "*", backend: term }]
backends:
  term:
    mode: terminate
    tls: { cert: "/nonexistent/c.pem", key: "/nonexistent/k.pem" }
    servers: ["10.0.0.1:443"]
"#));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("not supported for udp")),
            "{d:?}"
        );
    }

    #[test]
    fn redirect_https_allows_empty_servers() {
        let d = validate(&cfg(r#"
listeners:
  - name: r
    bind: ["0.0.0.0:80"]
    routes: [{ sni: "*", backend: to_https }]
backends:
  to_https:
    mode: redirect_https
"#));
        assert!(errors(&d).is_empty(), "{d:?}");
    }

    #[test]
    fn terminate_tcp_requires_tls() {
        let d = validate(&cfg(r#"
listeners:
  - name: dot
    bind: ["0.0.0.0:853"]
    routes: [{ sni: "*", backend: dot }]
backends:
  dot:
    mode: terminate_tcp
    servers: ["10.0.0.1:53"]
"#));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("requires a tls section")),
            "{d:?}"
        );
    }

    #[test]
    fn http_rules_respond_needs_status() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: api }]
backends:
  api:
    mode: terminate
    tls: { cert: "/nonexistent/c.pem", key: "/nonexistent/k.pem" }
    http_rules:
      - { path: "*", action: respond }
    servers: ["10.0.0.1:8080"]
"#));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("requires a status code")),
            "{d:?}"
        );
    }

    #[test]
    fn zero_timeout_is_error() {
        let d = validate(&cfg(r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: web }]
backends:
  web:
    servers: ["10.0.0.1:443"]
timeouts:
  handshake: 0
"#));
        assert!(
            errors(&d).iter().any(|e| e.path == "timeouts.handshake"),
            "{d:?}"
        );
    }
}
