//! Read-only admin/REST API — a foundation for a future web UI.
//!
//! `GET /status` (JSON), `GET /config` (YAML), `GET /healthz`. Optional bearer
//! token. Runs on a single core (not reuseport) since it's a control plane, not
//! a data path. Read-only for now: applying config changes needs the SIGHUP /
//! arc-swap reload path, which is still on the roadmap.

use crate::config::{Mode, Proto};
use crate::server::Shared;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use std::io;
use std::sync::Arc;
use std::time::Duration;

const HEAD_MAX: usize = 16 * 1024;

/// Accept loop for the admin listener. Spawned once (on core 0).
pub async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let shared = shared.clone();
                monoio::spawn(async move {
                    let _ = handle(stream, shared).await;
                });
            }
            Err(_) => monoio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

async fn handle(mut s: TcpStream, shared: Arc<Shared>) -> io::Result<()> {
    // Read the request head.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
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
    }

    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Bearer-token auth, if configured.
    let state = shared.state.load_full();
    if let Some(token) = state.cfg.admin.as_ref().and_then(|a| a.token.as_deref()) {
        let expected = format!("Bearer {token}");
        let authorized = head.split("\r\n").any(|l| {
            l.split_once(':').is_some_and(|(n, v)| {
                n.trim().eq_ignore_ascii_case("authorization") && v.trim() == expected
            })
        });
        if !authorized {
            return respond(&mut s, 401, "Unauthorized", "text/plain", b"unauthorized\n").await;
        }
    }

    if method != "GET" {
        return respond(&mut s, 405, "Method Not Allowed", "text/plain", b"method not allowed\n").await;
    }

    match path {
        "/healthz" => respond(&mut s, 200, "OK", "text/plain", b"ok\n").await,
        "/status" => {
            let body = status_json(&state, shared.started);
            respond(&mut s, 200, "OK", "application/json", body.as_bytes()).await
        }
        "/config" => {
            // The admin token is `skip_serializing`, so it never appears here.
            let body = serde_norway::to_string(&state.cfg).unwrap_or_default();
            respond(&mut s, 200, "OK", "application/yaml", body.as_bytes()).await
        }
        _ => respond(&mut s, 404, "Not Found", "text/plain", b"not found\n").await,
    }
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

/// Minimal JSON string escaping for the few controlled values we emit.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn respond(
    s: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
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
