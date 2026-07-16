//! Static config validation (`--test-config` / `-t`).
//!
//! Collects *all* problems in one pass (compiler-style, not fail-fast) so the
//! user can fix everything in one edit. The exact same function must be used
//! by the SIGHUP reload path: an invalid new config is rejected and the old
//! one keeps running.

use super::{Config, HttpAction, Mode, Proto, DEFAULT_QUEUE};
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
        // An API-only config (no routing yet, filled in later via the API) is
        // valid as long as the API is what's being served. Otherwise there's
        // nothing to do.
        if cfg.api.is_none() {
            d.push(Diagnostic::error(
                "listeners",
                "no listeners and no api section — nothing to do; add a listener or an `api` section",
            ));
        }
    }
    // Backends are only required once there are listeners routing to them;
    // referential integrity below flags any route pointing at a missing one.
    if !cfg.listeners.is_empty() && cfg.backends.is_empty() {
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

        if l.fast_open {
            if l.proto != Proto::Tcp {
                d.push(Diagnostic::error(
                    format!("listeners[{i}].fast_open"),
                    "TCP Fast Open applies to proto: tcp only",
                ));
            } else if let Some(msg) = tcp_fastopen_sysctl_issue() {
                d.push(Diagnostic::warning(format!("listeners[{i}].fast_open"), msg));
            }
        }
        if l.fast_open_qlen.is_some() && !l.fast_open {
            d.push(Diagnostic::warning(
                format!("listeners[{i}].fast_open_qlen"),
                "ignored — the queue only exists when fast_open is true",
            ));
        }
        // Accept queues: a zero-length queue silently disables the thing it
        // sizes (listen(0) accepts nothing useful; TFO qlen 0 turns TFO off),
        // which is never what someone typing the field meant.
        for (field, v, applies) in [
            ("backlog", l.backlog, l.proto == Proto::Tcp),
            ("fast_open_qlen", l.fast_open_qlen, l.fast_open),
        ] {
            let Some(v) = v else { continue };
            if v == 0 {
                d.push(Diagnostic::error(
                    format!("listeners[{i}].{field}"),
                    format!("must be > 0 (omit it for the default of {DEFAULT_QUEUE})"),
                ));
            } else if applies {
                if let Some(msg) = somaxconn_issue(field, v) {
                    d.push(Diagnostic::warning(format!("listeners[{i}].{field}"), msg));
                }
            }
        }
        if l.backlog.is_some() && l.proto != Proto::Tcp {
            d.push(Diagnostic::warning(
                format!("listeners[{i}].backlog"),
                "ignored — udp has no listen() accept queue",
            ));
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
                // Both terminate modes present a TLS cert to clients: the
                // backend's own `tls`, or the shared top-level `default_tls`.
                match cfg.effective_tls(b) {
                    None => d.push(Diagnostic::error(
                        format!("{bp}.tls"),
                        format!(
                            "mode \"{}\" requires a tls section (cert and key), \
                             or a top-level default_tls",
                            mode_name(b.mode)
                        ),
                    )),
                    Some(t) => {
                        // Point diagnostics at whichever source supplied the cert.
                        let src =
                            if b.tls.is_some() { format!("{bp}.tls") } else { "default_tls".into() };
                        for (field, p) in [("cert", &t.cert), ("key", &t.key)] {
                            check_readable(&mut d, format!("{src}.{field}"), p);
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
                                check_readable(&mut d, format!("{bp}.backend_tls.{field}"), path);
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
                        "http_rules are only applied in terminate and redirect_https modes",
                    ));
                }
            }
            Mode::RedirectHttps => {
                if !b.servers.is_empty() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.servers"),
                        "servers are ignored in redirect_https mode (it answers directly, no upstream)",
                    ));
                }
                if b.tls.is_some() {
                    d.push(Diagnostic::warning(
                        format!("{bp}.tls"),
                        "tls is ignored in redirect_https mode (it serves plaintext :80)",
                    ));
                }
                if b.fast_open {
                    d.push(Diagnostic::warning(
                        format!("{bp}.fast_open"),
                        "fast_open is ignored in redirect_https mode (it never connects to a backend)",
                    ));
                }
                // http_rules ARE honored here (plaintext responder); no warning.
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
                HttpAction::Respond => {
                    match r.status {
                        None => d.push(Diagnostic::error(
                            format!("{rpth}.status"),
                            "action \"respond\" requires a status code",
                        )),
                        Some(s) if !(100..600).contains(&s) => d.push(Diagnostic::error(
                            format!("{rpth}.status"),
                            format!("status {s} out of range (100-599)"),
                        )),
                        _ => {}
                    }
                    if r.to.is_some() {
                        d.push(Diagnostic::warning(
                            format!("{rpth}.to"),
                            "\"to\" is ignored for action \"respond\" (use \"redirect\")",
                        ));
                    }
                }
                HttpAction::Redirect => {
                    match &r.to {
                        None => d.push(Diagnostic::error(
                            format!("{rpth}.to"),
                            "action \"redirect\" requires \"to\" (the literal \"https\" \
                             or an absolute URL like \"https://example.com/\")",
                        )),
                        Some(t) if t != "https" && !t.contains("://") => {
                            d.push(Diagnostic::error(
                                format!("{rpth}.to"),
                                format!(
                                    "\"{t}\" is not a valid redirect target — use \"https\" \
                                     or an absolute URL (scheme://host/...)"
                                ),
                            ))
                        }
                        _ => {}
                    }
                    if let Some(s) = r.status {
                        if !(300..400).contains(&s) {
                            d.push(Diagnostic::error(
                                format!("{rpth}.status"),
                                format!("redirect status {s} must be 3xx (default 301)"),
                            ));
                        }
                    }
                }
                HttpAction::Forward => {
                    if r.status.is_some() {
                        d.push(Diagnostic::warning(
                            format!("{rpth}.status"),
                            "status is ignored for action \"forward\"",
                        ));
                    }
                    if b.mode == Mode::RedirectHttps {
                        d.push(Diagnostic::warning(
                            format!("{rpth}.action"),
                            "action \"forward\" has no servers to forward to in \
                             redirect_https mode",
                        ));
                    }
                }
            }
        }
        // http2 applies only to terminate, and gateways to HTTP/1.1 plaintext.
        if b.http2 && b.mode != Mode::Terminate {
            d.push(Diagnostic::warning(
                format!("{bp}.http2"),
                "http2 is only applied in terminate mode",
            ));
        }
        if b.http2 && b.mode == Mode::Terminate && b.backend_tls.is_some() {
            d.push(Diagnostic::error(
                format!("{bp}.http2"),
                "http2 termination forwards to the backend over HTTP/1.1 plaintext \
                 and cannot be combined with backend_tls (re-encrypt)",
            ));
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
    // keepalive is the one timeout where 0 is meaningful (disabled), so it sits
    // outside the loop above.
    if cfg.timeouts.keepalive > 86_400 {
        d.push(Diagnostic::warning(
            "timeouts.keepalive",
            format!("{}s is unusually large (more than 24h)", cfg.timeouts.keepalive),
        ));
    }

    // Management + metrics API bind address + optional TLS cert.
    if let Some(api) = &cfg.api {
        match api.bind.parse::<SocketAddr>() {
            Err(_) => {
                d.push(Diagnostic::error(
                    "api.bind",
                    format!("invalid address \"{}\" — expected IP:port", api.bind),
                ));
            }
            Ok(addr) if !addr.ip().is_loopback() => {
                if api.token.is_none() {
                    d.push(Diagnostic::warning(
                        "api.token",
                        "API on a non-loopback address without a token — anyone who can reach \
                         it can read /config and change the running config",
                    ));
                }
            }
            Ok(_) => {}
        }
        if let Some(t) = &api.tls {
            for (field, p) in [("cert", &t.cert), ("key", &t.key)] {
                check_readable(&mut d, format!("api.tls.{field}"), p);
            }
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

/// Returns a warning message if `net.ipv4.tcp_fastopen` is not 3 (client+server
/// enabled), i.e. the kernel will silently ignore the socket's `TCP_FASTOPEN`.
/// Unreadable sysctl (container, non-Linux) is not flagged — we can't tell.
fn tcp_fastopen_sysctl_issue() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen").ok()?;
    let v: u8 = raw.trim().parse().ok()?;
    (v != 3).then(|| {
        format!(
            "fast_open is enabled but net.ipv4.tcp_fastopen = {v} — the kernel will not \
             accept TFO connections; run \"sysctl -w net.ipv4.tcp_fastopen=3\" \
             (persist in /etc/sysctl.d/). The service still starts, TFO is just inactive"
        )
    })
}

/// Warn when an accept queue exceeds `net.core.somaxconn`: the kernel silently
/// clamps it, so the configured number would be a comfortable fiction.
/// Unreadable sysctl (container, non-Linux) is not flagged — we can't tell.
fn somaxconn_issue(field: &str, v: u32) -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/net/core/somaxconn").ok()?;
    let max: u32 = raw.trim().parse().ok()?;
    (v > max).then(|| {
        format!(
            "{field} = {v} exceeds net.core.somaxconn = {max} — the kernel will clamp the \
             queue to {max}; raise the sysctl (\"sysctl -w net.core.somaxconn={v}\", \
             persist in /etc/sysctl.d/) or lower {field}"
        )
    })
}

/// Cert/key readability check for `-t`. A missing file (or bad path) is a real
/// config error. A *permission* error is only a WARNING: the running service
/// reads certs via `CAP_DAC_READ_SEARCH` (see the systemd unit in install.sh),
/// so `-t` run as a user without that capability can be denied a file the
/// service will read fine — flagging that as an error would be a false alarm.
fn check_readable(d: &mut Vec<Diagnostic>, field: String, p: &std::path::Path) {
    if let Err(e) = std::fs::File::open(p) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            d.push(Diagnostic::warning(
                field,
                format!(
                    "permission denied reading \"{}\" — the service reads certs via \
                     CAP_DAC_READ_SEARCH, so this may still work at runtime; \
                     ensure the file exists and is readable by root",
                    p.display()
                ),
            ));
        } else {
            d.push(Diagnostic::error(field, format!("cannot read \"{}\": {e}", p.display())));
        }
    }
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
    fn fast_open_on_udp_is_an_error() {
        let d = validate(&cfg(r#"
listeners:
  - name: q
    bind: ["0.0.0.0:443"]
    proto: udp
    fast_open: true
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        let e = errors(&d);
        assert_eq!(e.len(), 1, "{d:?}");
        assert_eq!(e[0].path, "listeners[0].fast_open");
    }

    #[test]
    fn fast_open_on_tcp_is_never_an_error() {
        // Sysctl-dependent, so only assert it can't block startup.
        let d = validate(&cfg(r#"
listeners:
  - name: main
    bind: ["0.0.0.0:443"]
    proto: tcp
    fast_open: true
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        assert!(errors(&d).is_empty(), "{d:?}");
    }

    #[test]
    fn zero_length_accept_queues_are_errors() {
        let d = validate(&cfg(r#"
listeners:
  - name: main
    bind: ["0.0.0.0:443"]
    proto: tcp
    backlog: 0
    fast_open: true
    fast_open_qlen: 0
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        let paths: Vec<&str> = errors(&d).iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"listeners[0].backlog"), "{d:?}");
        assert!(paths.contains(&"listeners[0].fast_open_qlen"), "{d:?}");
    }

    #[test]
    fn queue_fields_warn_when_they_do_not_apply() {
        let d = validate(&cfg(r#"
listeners:
  - name: q
    bind: ["0.0.0.0:443"]
    proto: udp
    backlog: 2048
    routes:
      - { sni: "*", backend: web }
  - name: t
    bind: ["0.0.0.0:8443"]
    proto: tcp
    fast_open_qlen: 2048
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
"#));
        assert!(errors(&d).is_empty(), "{d:?}");
        let paths: Vec<&str> = warnings(&d).iter().map(|w| w.path.as_str()).collect();
        assert!(paths.contains(&"listeners[0].backlog"), "udp backlog: {d:?}");
        assert!(paths.contains(&"listeners[1].fast_open_qlen"), "qlen sans fast_open: {d:?}");
    }

    #[test]
    fn omitted_queues_fall_back_to_the_default() {
        let c = cfg(VALID);
        assert_eq!(c.listeners[0].backlog(), DEFAULT_QUEUE);
        assert_eq!(c.listeners[0].fast_open_qlen(), DEFAULT_QUEUE);
        assert!(validate(&c).is_empty());
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
    fn terminate_needs_cert_from_backend_or_default_tls() {
        let base = r#"
listeners:
  - name: l
    bind: ["0.0.0.0:443"]
    routes: [{ sni: "*", backend: t }]
backends:
  t:
    mode: terminate
    servers: ["10.0.0.1:8080"]
"#;
        // No backend tls and no default_tls -> "requires a tls section" error.
        let d = validate(&cfg(base));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("requires a tls section")),
            "{d:?}"
        );

        // Adding default_tls satisfies the requirement; the only remaining errors
        // point at the (nonexistent) default_tls files, proving inheritance ran.
        let with_default = format!("{base}default_tls:\n  cert: /no/such/cert.pem\n  key: /no/such/key.pem\n");
        let d = validate(&cfg(&with_default));
        assert!(
            !errors(&d).iter().any(|e| e.message.contains("requires a tls section")),
            "default_tls should satisfy the cert requirement: {d:?}"
        );
        assert!(errors(&d).iter().any(|e| e.path.starts_with("default_tls")), "{d:?}");
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
    fn redirect_rule_requires_to() {
        let d = validate(&cfg(r#"
listeners:
  - name: r
    bind: ["0.0.0.0:80"]
    routes: [{ sni: "*", backend: to_https }]
backends:
  to_https:
    mode: redirect_https
    http_rules:
      - { path: "*", action: redirect }
"#));
        assert!(
            errors(&d).iter().any(|e| e.message.contains("requires \"to\"")),
            "{d:?}"
        );
    }

    #[test]
    fn redirect_https_with_rules_has_no_warning() {
        let d = validate(&cfg(r#"
listeners:
  - name: r
    bind: ["0.0.0.0:80"]
    routes: [{ sni: "*", backend: to_https }]
backends:
  to_https:
    mode: redirect_https
    http_rules:
      - { path: "/health", action: respond, status: 200, body: "ok" }
      - { path: "*", action: redirect, to: "https" }
"#));
        assert!(errors(&d).is_empty(), "{d:?}");
        assert!(
            !warnings(&d).iter().any(|w| w.message.contains("http_rules")),
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
