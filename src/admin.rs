//! Unified management + metrics API — the control plane for a web UI.
//!
//! Reads: `GET /status` (JSON), `GET /config` (YAML), `GET /healthz`,
//! `GET /metrics` (Prometheus text), `GET /version`.
//! Writes (require a configured `api.token`): `PUT /config` (replace the
//! config file), `POST /reload` (re-read it from disk), `POST /restart`
//! (re-exec the process — the privilege-free equivalent of a service restart),
//! `POST /update` (fetch the latest release, install it, and re-exec).
//!
//! One bind, one token: when `api.token` is set every endpoint (metrics
//! included) requires it. Runs on a single core (not reuseport) since it's a
//! control plane, not a data path. Optionally served over TLS (`api.tls` /
//! `default_tls`).

use crate::config::{Mode, Proto};
use crate::server::{Applied, Shared};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::TcpListener;
use monoio_rustls::TlsAcceptor;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const HEAD_MAX: usize = 16 * 1024;
/// Cap on a `PUT /config` body — a config file is a few KiB; anything past this
/// is refused rather than buffered.
const BODY_MAX: usize = 1024 * 1024;
/// Whole-connection deadline (TLS handshake + request + response). Bounds the
/// buffers a slowloris-style client can pin on the control plane.
const CONN_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept loop for the admin listener. Spawned once (on core 0). `acceptor`
/// is `Some` when the API is served over TLS.
pub async fn serve(listener: TcpListener, shared: Arc<Shared>, acceptor: Option<TlsAcceptor>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let shared = shared.clone();
                let acceptor = acceptor.clone();
                monoio::spawn(async move {
                    let _ = monoio::time::timeout(CONN_TIMEOUT, async move {
                        match acceptor {
                            Some(acc) => {
                                if let Ok(tls) = acc.accept(stream).await {
                                    let _ = handle(tls, shared).await;
                                }
                            }
                            None => {
                                let _ = handle(stream, shared).await;
                            }
                        }
                    })
                    .await;
                });
            }
            Err(_) => monoio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

async fn handle<S>(mut s: S, shared: Arc<Shared>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    // Read the request head (up to and including CRLFCRLF).
    let mut buf: Vec<u8> = Vec::new();
    let head_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > HEAD_MAX {
            return respond(&mut s, 431, "Request Header Fields Too Large", "text/plain", b"").await;
        }
        let tmp = vec![0u8; 4096];
        let (r, tmp) = s.read(tmp).await;
        let n = r?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let request_line = head.split("\r\n").next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let state = shared.state.load_full();
    let token = state.cfg.api.as_ref().and_then(|a| a.token.as_deref());
    let is_write = matches!(method, "PUT" | "POST");

    // Writes are gated behind a configured token: without one they are refused,
    // so the config can never be changed unauthenticated.
    if is_write && token.is_none() {
        return respond(
            &mut s,
            403,
            "Forbidden",
            "application/json",
            b"{\"error\":\"write endpoints require api.token to be configured\"}\n",
        )
        .await;
    }
    // When a token is set, every request must present it (reads included).
    if let Some(tok) = token {
        let presented = header_value(&head, "authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        if !presented.is_some_and(|p| ct_eq(p.as_bytes(), tok.as_bytes())) {
            return respond(&mut s, 401, "Unauthorized", "text/plain", b"unauthorized\n").await;
        }
    }

    match (method, path) {
        ("GET", "/healthz") => respond(&mut s, 200, "OK", "text/plain", b"ok\n").await,
        ("GET", "/status") => {
            let body = status_json(&state, shared.started);
            respond(&mut s, 200, "OK", "application/json", body.as_bytes()).await
        }
        ("GET", "/config") => {
            // The api token is `skip_serializing`, so it never appears here.
            let body = serde_norway::to_string(&state.cfg).unwrap_or_default();
            respond(&mut s, 200, "OK", "application/yaml", body.as_bytes()).await
        }
        ("GET", "/metrics") => {
            let body = crate::metrics::render();
            respond(&mut s, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", body.as_bytes())
                .await
        }
        ("GET", "/version") => {
            let body = format!(
                "{{\"version\":\"{}\"}}\n",
                esc(crate::update::current_version())
            );
            respond(&mut s, 200, "OK", "application/json", body.as_bytes()).await
        }
        ("PUT", "/config") => put_config(&mut s, &shared, &head, &buf, head_end).await,
        ("POST", "/reload") => reload(&mut s, &shared).await,
        ("POST", "/restart") => restart(&mut s, &shared).await,
        ("POST", "/update") => update(&mut s).await,
        ("GET", _) | ("PUT", _) | ("POST", _) => {
            respond(&mut s, 404, "Not Found", "text/plain", b"not found\n").await
        }
        _ => respond(&mut s, 405, "Method Not Allowed", "text/plain", b"method not allowed\n").await,
    }
}

/// `PUT /config` — validate the body, atomically replace the config file, then
/// apply it (hot-swap or restart). On any validation error nothing is written.
async fn put_config<S>(
    s: &mut S,
    shared: &Arc<Shared>,
    head: &str,
    buf: &[u8],
    head_end: usize,
) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    let len = match header_value(head, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        Some(n) => n,
        None => {
            return respond(s, 411, "Length Required", "application/json",
                b"{\"error\":\"Content-Length required for PUT /config\"}\n").await;
        }
    };
    if len > BODY_MAX {
        return respond(s, 413, "Payload Too Large", "application/json",
            b"{\"error\":\"config body too large\"}\n").await;
    }

    // Body bytes already read past the head, plus however many remain.
    let mut body: Vec<u8> = buf[head_end..].to_vec();
    while body.len() < len {
        let tmp = vec![0u8; 8192];
        let (r, tmp) = s.read(tmp).await;
        let n = r?;
        if n == 0 {
            return respond(s, 400, "Bad Request", "application/json",
                b"{\"error\":\"connection closed before full body received\"}\n").await;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);

    let text = match std::str::from_utf8(&body) {
        Ok(t) => t,
        Err(_) => {
            return respond(s, 400, "Bad Request", "application/json",
                b"{\"error\":\"body is not valid UTF-8\"}\n").await;
        }
    };

    // Parse (YAML/type errors) then run the same static validation as `-t`.
    let cfg = match crate::config::parse_str(text) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{{\"error\":\"parse: {}\"}}\n", esc(&e));
            return respond(s, 400, "Bad Request", "application/json", msg.as_bytes()).await;
        }
    };
    if let Err(body) = validation_errors(&cfg) {
        return respond(s, 400, "Bad Request", "application/json", body.as_bytes()).await;
    }

    // GET /config redacts api.token, so a GET → edit → PUT round-trip would
    // silently strip the token from the file, leaving the API unauthenticated
    // after the next restart. Refuse that; removing auth deliberately means
    // editing the file on disk.
    let cur_token_set = shared
        .state
        .load()
        .cfg
        .api
        .as_ref()
        .is_some_and(|a| a.token.is_some());
    if cur_token_set && cfg.api.as_ref().is_some_and(|a| a.token.is_none()) {
        return respond(s, 400, "Bad Request", "application/json",
            b"{\"error\":\"api.token is missing (GET /config redacts it) - include the token in the body, or remove it by editing the file on disk\"}\n").await;
    }

    // Write atomically (temp + rename) so a crash mid-write can't corrupt it.
    if let Err(e) = write_atomic(shared.config_path(), &body) {
        let msg = format!(
            "{{\"error\":\"cannot write config file {}: {}\"}}\n",
            esc(&shared.config_path().display().to_string()),
            esc(&e.to_string())
        );
        return respond(s, 500, "Internal Server Error", "application/json", msg.as_bytes()).await;
    }

    match shared.apply_config(cfg) {
        Applied::HotSwapped => {
            respond(s, 200, "OK", "application/json",
                b"{\"status\":\"ok\",\"applied\":\"reload\",\"downtime\":false}\n").await
        }
        Applied::RestartRequired => {
            respond(s, 200, "OK", "application/json",
                b"{\"status\":\"ok\",\"applied\":\"restart\",\"downtime\":true}\n").await?;
            crate::server::fast_restart()
        }
    }
}

/// `POST /reload` — re-read the on-disk config and apply it (like SIGHUP).
async fn reload<S>(s: &mut S, shared: &Arc<Shared>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    let cfg = match load_and_check(shared.config_path()) {
        Ok(c) => c,
        Err(body) => return respond(s, 400, "Bad Request", "application/json", body.as_bytes()).await,
    };
    match shared.apply_config(cfg) {
        Applied::HotSwapped => {
            respond(s, 200, "OK", "application/json",
                b"{\"status\":\"ok\",\"applied\":\"reload\",\"downtime\":false}\n").await
        }
        Applied::RestartRequired => {
            respond(s, 200, "OK", "application/json",
                b"{\"status\":\"ok\",\"applied\":\"restart\",\"downtime\":true}\n").await?;
            crate::server::fast_restart()
        }
    }
}

/// `POST /restart` — validate the on-disk config, then re-exec the process,
/// dropping all connections and rebinding immediately (no drain). A broken
/// on-disk config aborts the restart and keeps the running process alive.
async fn restart<S>(s: &mut S, shared: &Arc<Shared>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    if let Err(body) = load_and_check(shared.config_path()) {
        return respond(s, 400, "Bad Request", "application/json", body.as_bytes()).await;
    }
    respond(s, 200, "OK", "application/json",
        b"{\"status\":\"ok\",\"applied\":\"restart\",\"downtime\":true}\n").await?;
    crate::server::fast_restart()
}

/// `POST /update` — check for a newer release and, if one exists, install it and
/// re-exec into the new binary.
///
/// The **check** (a small GitHub API call) runs synchronously so the response can
/// report `updated:false` when already current, or announce the version it's
/// moving to. The **download + replace + restart** then runs on a detached
/// thread (it can outlast the request's slowloris deadline, and it re-execs the
/// process — the connection drops either way). A client confirms the result by
/// polling `GET /version` after the service comes back; a failed download is
/// logged and leaves the running version unchanged.
async fn update<S>(s: &mut S) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    match run_blocking(|| crate::update::check(false)).await {
        Err(e) => {
            let msg = format!("{{\"error\":\"update check failed: {}\"}}\n", esc(&e));
            respond(s, 502, "Bad Gateway", "application/json", msg.as_bytes()).await
        }
        Ok(crate::update::Plan::AlreadyLatest { version }) => {
            let body = format!(
                "{{\"status\":\"ok\",\"updated\":false,\"version\":\"{}\"}}\n",
                esc(&version)
            );
            respond(s, 200, "OK", "application/json", body.as_bytes()).await
        }
        Ok(crate::update::Plan::Available { from, to, tag, arch }) => {
            let body = format!(
                "{{\"status\":\"ok\",\"updated\":true,\"from\":\"{}\",\"to\":\"{}\",\"restarting\":true}}\n",
                esc(&from),
                esc(&to)
            );
            respond(s, 200, "OK", "application/json", body.as_bytes()).await?;
            // Detached: survives this connection, then re-execs the whole process.
            std::thread::spawn(move || match crate::update::apply(&tag, arch) {
                Ok(()) => crate::server::fast_restart(),
                Err(e) => tracing::error!(error = %e, "self-update failed; version unchanged"),
            });
            Ok(())
        }
    }
}

/// Run a blocking closure off the monoio runtime thread, awaiting its result
/// without stalling core 0's data path. Used for the update check's network I/O.
async fn run_blocking<T, F>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    loop {
        if let Ok(v) = rx.try_recv() {
            return v;
        }
        monoio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Load + validate a config file, returning a JSON error body on failure.
fn load_and_check(path: &Path) -> Result<crate::config::Config, String> {
    let cfg = crate::config::load(path)
        .map_err(|e| format!("{{\"error\":\"parse: {}\"}}\n", esc(&e)))?;
    validation_errors(&cfg)?;
    Ok(cfg)
}

/// Run the same static validation as `-t`; errors come back as a JSON body.
fn validation_errors(cfg: &crate::config::Config) -> Result<(), String> {
    let diags = crate::config::validate::validate(cfg);
    let errors: Vec<String> = diags
        .iter()
        .filter(|d| d.level == crate::config::validate::Level::Error)
        .map(|d| format!("{{\"path\":\"{}\",\"message\":\"{}\"}}", esc(&d.path), esc(&d.message)))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("{{\"error\":\"validation failed\",\"errors\":[{}]}}\n", errors.join(",")))
    }
}

/// Constant-time byte comparison for the bearer token, so response timing
/// doesn't leak how many leading bytes of a guess were right.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Write `bytes` to `path` via a temp file in the same directory + rename, so a
/// reader never sees a half-written config. The temp file is created with the
/// target's existing permissions (0600 for a new file) — the config holds the
/// admin token, and a umask-default 0644 temp would make it world-readable
/// after the rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let res = (|| {
        std::fs::write(&tmp, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(path)
                .map(|m| m.permissions())
                .unwrap_or_else(|_| std::fs::Permissions::from_mode(0o600));
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn status_json(state: &crate::server::State, started: std::time::Instant) -> String {
    let uptime = started.elapsed().as_secs();
    let listeners = state
        .cfg
        .listeners
        .iter()
        .map(|l| {
            let binds = l
                .bind
                .iter()
                .map(|b| format!("\"{}\"", esc(b)))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"name\":\"{}\",\"proto\":\"{}\",\"bind\":[{}]}}",
                esc(&l.name),
                proto_str(l.proto),
                binds
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let backends = state
        .cfg
        .backends
        .iter()
        .map(|(n, b)| {
            format!(
                "{{\"name\":\"{}\",\"mode\":\"{}\",\"servers\":{}}}",
                esc(n),
                mode_str(b.mode),
                b.servers.len()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"version\":\"{}\",\"uptime_secs\":{},\"listeners\":[{}],\"backends\":[{}]}}\n",
        env!("CARGO_PKG_VERSION"),
        uptime,
        listeners,
        backends
    )
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Passthrough => "passthrough",
        Mode::Terminate => "terminate",
        Mode::TerminateTcp => "terminate_tcp",
        Mode::RedirectHttps => "redirect_https",
    }
}

/// Minimal JSON string escaping for the values we emit (serde error messages
/// can carry newlines and, in principle, other control characters).
fn esc(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

async fn respond<S>(
    s: &mut S,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    let (r, _) = s.write_all(out).await;
    r?;
    let _ = s.shutdown().await;
    Ok(())
}
