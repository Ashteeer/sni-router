//! `mode: terminate` — the router terminates the client's TLS itself, injects
//! `X-Real-IP` / `X-Forwarded-*` headers, and forwards to the backend as
//! HTTP/1.1 (optionally re-encrypted with TLS + mTLS).
//!
//! TCP only; QUIC/HTTP3 termination is out of scope. HTTP/1.1 is handled in a
//! sequential request/response loop (which also copes with pipelining, since
//! bodies are precisely framed), with `Upgrade`/WebSocket switching to a raw
//! full-duplex tunnel. Optional per-path rules answer some requests with a
//! synthetic `direct_response` instead of forwarding.
//!
//! [`handle_raw`] is the sibling entry point for `mode: terminate_tcp`: it
//! terminates TLS and forwards the decrypted stream to the backend as raw TCP
//! (no HTTP parsing) — e.g. DoT on `:853`.

use crate::config::{Backend, Headers, HttpAction, HttpRule};
use arc_swap::ArcSwap;
use monoio::buf::IoBuf;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, PrefixedReadIo, Split, Splitable};
use monoio::net::TcpStream;
use monoio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const CERT_POLL: Duration = Duration::from_secs(5);

const HEAD_MAX: usize = 64 * 1024;
const IO_CHUNK: usize = 16 * 1024;

/// Precomputed TLS material for one terminate backend.
pub struct TerminateCtx {
    acceptor: TlsAcceptor,
    /// `Some` => re-encrypt to the backend over TLS.
    backend: Option<BackendConnector>,
    headers: Headers,
    /// Per-path request rules (terminate mode only; empty = forward all).
    http_rules: Vec<crate::config::HttpRule>,
    /// Live-swappable cert (updated by the reload watcher).
    resolver: Arc<SwapResolver>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

/// rustls cert resolver whose certificate can be swapped atomically at runtime,
/// so certbot/lego renewals are picked up with zero downtime.
struct SwapResolver {
    cert: ArcSwap<CertifiedKey>,
}

impl std::fmt::Debug for SwapResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwapResolver")
    }
}

impl ResolvesServerCert for SwapResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.cert.load_full())
    }
}

/// One cert file to watch for changes.
pub struct CertWatch {
    resolver: Arc<SwapResolver>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert: PathBuf,
    key: PathBuf,
}

struct BackendConnector {
    connector: TlsConnector,
    sni: Option<String>,
}

impl TerminateCtx {
    /// Build the TLS contexts for every terminate backend. Returns the map
    /// plus the list of cert files to watch for renewal; backends that fail to
    /// build are reported and skipped.
    pub fn build_all(
        backends: &std::collections::BTreeMap<String, Backend>,
    ) -> (HashMapCtx, Vec<CertWatch>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut out = std::collections::HashMap::new();
        let mut watch = Vec::new();
        for (name, b) in backends {
            if !matches!(b.mode, crate::config::Mode::Terminate | crate::config::Mode::TerminateTcp) {
                continue;
            }
            match Self::build_one(b, &provider) {
                Ok(ctx) => {
                    watch.push(CertWatch {
                        resolver: ctx.resolver.clone(),
                        provider: provider.clone(),
                        cert: ctx.cert_path.clone(),
                        key: ctx.key_path.clone(),
                    });
                    out.insert(name.clone(), ctx);
                }
                Err(e) => tracing::error!(backend = %name, error = %e, "terminate TLS setup failed"),
            }
        }
        (out, watch)
    }

    fn build_one(b: &Backend, provider: &Arc<rustls::crypto::CryptoProvider>) -> Result<Self, String> {
        let tls = b.tls.as_ref().ok_or("terminate backend missing tls")?;
        let ck = build_certified_key(&tls.cert, &tls.key, provider)?;
        let resolver = Arc::new(SwapResolver { cert: ArcSwap::new(ck) });
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        // HTTP terminate advertises http/1.1; the raw (terminate_tcp) tunnel
        // leaves ALPN unset so clients negotiating e.g. "dot" still connect.
        if b.mode == crate::config::Mode::Terminate {
            server.alpn_protocols = vec![b"http/1.1".to_vec()];
        }

        // Re-encrypt / mTLS only applies to HTTP terminate; raw tunnels plaintext.
        let backend = match (b.mode, &b.backend_tls) {
            (crate::config::Mode::Terminate, Some(bt)) => {
                let mut roots = RootCertStore::empty();
                match &bt.ca {
                    Some(ca) => {
                        for c in load_certs(ca)? {
                            roots.add(c).map_err(|e| e.to_string())?;
                        }
                    }
                    None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                }
                let builder = ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .with_root_certificates(roots);
                let mut client = match (&bt.client_cert, &bt.client_key) {
                    (Some(c), Some(k)) => builder
                        .with_client_auth_cert(load_certs(c)?, load_key(k)?)
                        .map_err(|e| e.to_string())?,
                    _ => builder.with_no_client_auth(),
                };
                if bt.insecure_skip_verify {
                    client
                        .dangerous()
                        .set_certificate_verifier(Arc::new(NoVerify(provider.clone())));
                }
                client.alpn_protocols = vec![b"http/1.1".to_vec()];
                Some(BackendConnector {
                    connector: TlsConnector::from(Arc::new(client)),
                    sni: bt.sni.clone(),
                })
            }
            _ => None, // plaintext to backend (or raw mode)
        };

        let http_rules = if b.mode == crate::config::Mode::Terminate {
            b.http_rules.clone()
        } else {
            Vec::new()
        };

        Ok(TerminateCtx {
            acceptor: TlsAcceptor::from(Arc::new(server)),
            backend,
            headers: b.headers,
            http_rules,
            resolver,
            cert_path: tls.cert.clone(),
            key_path: tls.key.clone(),
        })
    }
}

type HashMapCtx = std::collections::HashMap<String, TerminateCtx>;

fn build_certified_key(
    cert: &std::path::Path,
    key: &std::path::Path,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<CertifiedKey>, String> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let signing = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// Watch terminate cert files and hot-swap the cert when they change (e.g. after
/// a certbot/lego renewal), with zero downtime. Runs on a dedicated system
/// thread — off the monoio data path.
pub fn spawn_cert_watcher(watch: Vec<CertWatch>) {
    if watch.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let mut mtimes: Vec<Option<SystemTime>> = watch.iter().map(|w| mtime(&w.cert)).collect();
        loop {
            std::thread::sleep(CERT_POLL);
            for (i, w) in watch.iter().enumerate() {
                let m = mtime(&w.cert);
                if m.is_some() && m != mtimes[i] {
                    match build_certified_key(&w.cert, &w.key, &w.provider) {
                        Ok(ck) => {
                            w.resolver.cert.store(ck);
                            mtimes[i] = m;
                            tracing::info!(cert = %w.cert.display(), "reloaded certificate");
                        }
                        Err(e) => {
                            tracing::error!(cert = %w.cert.display(), error = %e, "cert reload failed")
                        }
                    }
                }
            }
        }
    });
}

fn mtime(p: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Handle one terminate connection. `prefix` is the ClientHello bytes already
/// read off the socket (replayed into the TLS handshake); `backend` is an
/// already-connected TCP stream (so pool retry/health lives in one place).
pub async fn handle(
    prefix: Vec<u8>,
    client: TcpStream,
    peer: SocketAddr,
    sni: &str,
    backend: TcpStream,
    ctx: &TerminateCtx,
) -> io::Result<()> {
    let io = PrefixedReadIo::new(client, Cursor::new(prefix));
    let tls = ctx
        .acceptor
        .accept(io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls accept: {e}")))?;

    match &ctx.backend {
        None => http_forward(Buf::new(tls), Buf::new(backend), peer, &ctx.headers, &ctx.http_rules).await,
        Some(bc) => {
            let name = bc.sni.clone().unwrap_or_else(|| sni.to_string());
            let domain = ServerName::try_from(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid backend SNI"))?;
            let btls = bc
                .connector
                .connect(domain, backend)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("backend tls: {e}")))?;
            http_forward(Buf::new(tls), Buf::new(btls), peer, &ctx.headers, &ctx.http_rules).await
        }
    }
}

/// `mode: terminate_tcp` — terminate the client's TLS, then forward the
/// decrypted bytes to the backend as a **raw TCP tunnel** (no HTTP parsing).
/// `prefix` is the ClientHello already read; `proxy_header` (optional PROXY
/// protocol) is sent to the backend before the tunnel starts. Returns
/// `(bytes_up, bytes_down)`.
pub async fn handle_raw(
    prefix: Vec<u8>,
    client: TcpStream,
    backend: TcpStream,
    ctx: &TerminateCtx,
    proxy_header: Option<Vec<u8>>,
) -> io::Result<(u64, u64)> {
    let io = PrefixedReadIo::new(client, Cursor::new(prefix));
    let tls = ctx
        .acceptor
        .accept(io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls accept: {e}")))?;

    let mut backend = backend;
    if let Some(h) = proxy_header {
        backend.write_all(h).await.0?;
    }

    let (cr, cw) = Splitable::into_split(tls);
    let (br, bw) = backend.into_split();
    let c2b = monoio::spawn(tunnel_copy(cr, bw)); // client -> backend
    let down = tunnel_copy(br, cw).await; // backend -> client
    let up = c2b.await;
    Ok((up, down))
}

// ---------------------------------------------------------------------------
// HTTP/1.1 forwarding
// ---------------------------------------------------------------------------

/// A stream with a read-ahead buffer. Writes go straight to the stream.
struct Buf<S> {
    s: S,
    data: Vec<u8>,
}

impl<S: AsyncReadRent + AsyncWriteRent> Buf<S> {
    fn new(s: S) -> Self {
        Buf { s, data: Vec::new() }
    }

    /// Read more bytes into the buffer. Returns false on EOF.
    async fn fill(&mut self) -> io::Result<bool> {
        let tmp = vec![0u8; IO_CHUNK];
        let (r, tmp) = self.s.read(tmp).await;
        let n = r?;
        if n == 0 {
            return Ok(false);
        }
        self.data.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    async fn write_all(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        let (r, _) = self.s.write_all(bytes).await;
        r.map(|_| ())
    }

    /// Read an HTTP head (up to and including CRLFCRLF). `None` at a clean EOF
    /// on a message boundary.
    async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = find(&self.data, b"\r\n\r\n") {
                return Ok(Some(self.data.drain(..pos + 4).collect()));
            }
            if self.data.len() > HEAD_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too large"));
            }
            if !self.fill().await? {
                return if self.data.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in HTTP head"))
                };
            }
        }
    }

    async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = find(&self.data, b"\r\n") {
                return Ok(self.data.drain(..pos + 2).collect());
            }
            if self.data.len() > HEAD_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk line too large"));
            }
            if !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in chunk line"));
            }
        }
    }
}

/// Forward exactly `n` body bytes from `src` to `dst`, streaming.
async fn forward_n<S, D>(src: &mut Buf<S>, dst: &mut Buf<D>, mut n: usize) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
    D: AsyncReadRent + AsyncWriteRent,
{
    while n > 0 {
        if src.data.is_empty() && !src.fill().await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in body"));
        }
        let take = n.min(src.data.len());
        let chunk: Vec<u8> = src.data.drain(..take).collect();
        dst.write_all(chunk).await?;
        n -= take;
    }
    Ok(())
}

/// Forward a chunked body verbatim (preserving the chunk framing).
async fn forward_chunked<S, D>(src: &mut Buf<S>, dst: &mut Buf<D>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
    D: AsyncReadRent + AsyncWriteRent,
{
    loop {
        let line = src.read_line().await?;
        // size is hex up to an optional ';' extension.
        let hex = line
            .split(|&b| b == b';' || b == b'\r')
            .next()
            .unwrap_or(&[]);
        let size = usize::from_str_radix(std::str::from_utf8(hex).unwrap_or("x").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        dst.write_all(line).await?;
        if size == 0 {
            // Trailers until a blank line.
            loop {
                let l = src.read_line().await?;
                let done = l == b"\r\n";
                dst.write_all(l).await?;
                if done {
                    break;
                }
            }
            return Ok(());
        }
        forward_n(src, dst, size).await?;
        let crlf = src.read_line().await?; // trailing CRLF after chunk data
        dst.write_all(crlf).await?;
    }
}

/// Forward everything until `src` EOF (HTTP/1.0-style / `Connection: close`).
async fn forward_to_eof<S, D>(src: &mut Buf<S>, dst: &mut Buf<D>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
    D: AsyncReadRent + AsyncWriteRent,
{
    loop {
        if !src.data.is_empty() {
            let chunk = std::mem::take(&mut src.data);
            dst.write_all(chunk).await?;
        }
        if !src.fill().await? {
            return Ok(());
        }
    }
}

async fn http_forward<C, B>(
    mut client: Buf<C>,
    mut backend: Buf<B>,
    peer: SocketAddr,
    headers: &Headers,
    rules: &[HttpRule],
) -> io::Result<()>
where
    C: AsyncReadRent + AsyncWriteRent + Split + 'static,
    B: AsyncReadRent + AsyncWriteRent + Split + 'static,
{
    loop {
        // --- request ---
        let head = match client.read_head().await? {
            Some(h) => h,
            None => return Ok(()), // client done
        };

        // Path gating / direct_response: a matching `respond` rule answers the
        // client directly (after draining its request body) without touching the
        // backend. Non-matching requests (or `forward` rules) fall through.
        if let Some(rule) = match_rule(rules, request_path(&head)) {
            if rule.action == HttpAction::Respond {
                skip_body(&mut client, &head).await?;
                client.write_all(direct_response(rule)).await?;
                continue;
            }
        }

        let (rewritten, req) = rewrite_request(&head, peer, headers)?;
        backend.write_all(rewritten).await?;
        match body_len(&head, true, false)? {
            Body::None => {}
            Body::Length(n) => forward_n(&mut client, &mut backend, n).await?,
            Body::Chunked => forward_chunked(&mut client, &mut backend).await?,
            Body::UntilEof => forward_to_eof(&mut client, &mut backend).await?,
        }
        let is_head = req.eq_ignore_ascii_case("HEAD");

        // --- response ---
        let rhead = match backend.read_head().await? {
            Some(h) => h,
            None => return Ok(()), // backend closed
        };
        let status = status_of(&rhead);
        let body = body_len(&rhead, false, is_head)?; // parse before we move rhead
        client.write_all(rhead).await?;
        // 101 Switching Protocols (WebSocket / other Upgrade): the framing ends
        // here — hand off to a raw full-duplex tunnel.
        if status == Some(101) {
            return upgrade_tunnel(client, backend).await;
        }
        match body {
            Body::None => {}
            Body::Length(n) => forward_n(&mut backend, &mut client, n).await?,
            Body::Chunked => forward_chunked(&mut backend, &mut client).await?,
            Body::UntilEof => {
                forward_to_eof(&mut backend, &mut client).await?;
                return Ok(()); // "until EOF" means the connection is over
            }
        }
    }
}

/// Parse the status code from an HTTP response head.
fn status_of(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\r').next()?;
    let text = std::str::from_utf8(line).ok()?;
    text.split_whitespace().nth(1)?.parse().ok()
}

/// After a `101`, tunnel bytes in both directions with no HTTP framing.
async fn upgrade_tunnel<C, B>(client: Buf<C>, backend: Buf<B>) -> io::Result<()>
where
    C: AsyncReadRent + AsyncWriteRent + Split + 'static,
    B: AsyncReadRent + AsyncWriteRent + Split + 'static,
{
    let Buf { s: cs, data: cleft } = client;
    let Buf { s: bs, data: bleft } = backend;
    let (cr, mut cw) = Splitable::into_split(cs);
    let (br, mut bw) = Splitable::into_split(bs);
    // Drain whatever each side already read past the handshake.
    if !bleft.is_empty() {
        cw.write_all(bleft).await.0?;
    }
    if !cleft.is_empty() {
        bw.write_all(cleft).await.0?;
    }
    let c2b = monoio::spawn(tunnel_copy(cr, bw));
    tunnel_copy(br, cw).await;
    let _ = c2b.await;
    Ok(())
}

/// Copy one direction until EOF, closing the write side. Returns bytes copied.
async fn tunnel_copy<R, W>(mut r: R, mut w: W) -> u64
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; IO_CHUNK];
    loop {
        let (res, b) = r.read(buf).await;
        buf = b;
        let n = match res {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total += n as u64;
        let (wres, slice) = w.write_all(buf.slice(..n)).await;
        buf = slice.into_inner();
        if wres.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
    total
}

enum Body {
    None,
    Length(usize),
    Chunked,
    UntilEof,
}

/// Determine body framing from a head. `is_request` picks request vs response
/// rules; `head_response` marks a response to a HEAD request (never has a body).
fn body_len(head: &[u8], is_request: bool, head_response: bool) -> io::Result<Body> {
    let text = String::from_utf8_lossy(head);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut status: Option<u16> = None;

    for (i, line) in text.split("\r\n").enumerate() {
        if i == 0 {
            if !is_request {
                // "HTTP/1.1 200 OK"
                status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
            }
            continue;
        }
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                // Ambiguous framing (both CL and TE) is a smuggling risk.
                content_length = value.parse().ok();
            } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }

    if chunked && content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "both Content-Length and Transfer-Encoding present (possible request smuggling)",
        ));
    }

    if is_request {
        if chunked {
            return Ok(Body::Chunked);
        }
        return Ok(content_length.map_or(Body::None, Body::Length));
    }

    // Response.
    if head_response {
        return Ok(Body::None);
    }
    if let Some(s) = status {
        if (100..200).contains(&s) || s == 204 || s == 304 {
            return Ok(Body::None);
        }
    }
    if chunked {
        return Ok(Body::Chunked);
    }
    Ok(content_length.map_or(Body::UntilEof, Body::Length))
}

/// Rewrite a request head, injecting the configured forwarding headers.
/// Returns the new head bytes and the request method.
fn rewrite_request(head: &[u8], peer: SocketAddr, cfg: &Headers) -> io::Result<(Vec<u8>, String)> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let method = request_line.split_whitespace().next().unwrap_or("").to_string();

    let mut out = Vec::with_capacity(head.len() + 128);
    out.extend_from_slice(request_line.as_bytes());
    out.extend_from_slice(b"\r\n");

    let mut existing_xff: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        // Drop headers we manage so a client can't spoof them.
        if cfg.x_real_ip && lower == "x-real-ip" {
            continue;
        }
        if cfg.x_forwarded_proto && lower == "x-forwarded-proto" {
            continue;
        }
        if cfg.x_forwarded_for && lower == "x-forwarded-for" {
            existing_xff = line.split_once(':').map(|(_, v)| v.trim().to_string());
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    let ip = peer.ip();
    if cfg.x_real_ip {
        out.extend_from_slice(format!("X-Real-IP: {ip}\r\n").as_bytes());
    }
    if cfg.x_forwarded_proto {
        out.extend_from_slice(b"X-Forwarded-Proto: https\r\n");
    }
    if cfg.x_forwarded_for {
        let xff = match existing_xff {
            Some(prev) => format!("{prev}, {ip}"),
            None => ip.to_string(),
        };
        out.extend_from_slice(format!("X-Forwarded-For: {xff}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok((out, method))
}

// ---------------------------------------------------------------------------
// path rules / direct_response
// ---------------------------------------------------------------------------

/// The request target from an HTTP head ("GET /path HTTP/1.1" -> "/path").
fn request_path(head: &[u8]) -> &str {
    let line = match head.split(|&b| b == b'\r' || b == b'\n').next() {
        Some(l) => l,
        None => return "",
    };
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.split_whitespace().nth(1))
        .unwrap_or("")
}

/// First rule whose path prefix (or `*`) matches; `None` = forward as usual.
fn match_rule<'a>(rules: &'a [HttpRule], path: &str) -> Option<&'a HttpRule> {
    rules
        .iter()
        .find(|r| r.path == "*" || path.starts_with(r.path.as_str()))
}

/// Render a synthetic `respond` rule into an HTTP/1.1 response (keep-alive, so
/// the connection stays usable for the next request).
fn direct_response(rule: &HttpRule) -> Vec<u8> {
    let status = rule.status.unwrap_or(200);
    let reason = reason_phrase(status);
    let ctype = rule.content_type.as_deref().unwrap_or("text/plain");
    let body = rule.body.as_bytes();
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\n\
         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Read and discard a request body (so the next request head stays aligned when
/// we answered this one with a direct response).
async fn skip_body<S>(src: &mut Buf<S>, head: &[u8]) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    match body_len(head, true, false)? {
        Body::None => Ok(()),
        Body::Length(n) => discard_n(src, n).await,
        Body::Chunked => discard_chunked(src).await,
        Body::UntilEof => loop {
            src.data.clear();
            if !src.fill().await? {
                return Ok(());
            }
        },
    }
}

async fn discard_n<S>(src: &mut Buf<S>, mut n: usize) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    while n > 0 {
        if src.data.is_empty() && !src.fill().await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in body"));
        }
        let take = n.min(src.data.len());
        src.data.drain(..take);
        n -= take;
    }
    Ok(())
}

async fn discard_chunked<S>(src: &mut Buf<S>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    loop {
        let line = src.read_line().await?;
        let hex = line.split(|&b| b == b';' || b == b'\r').next().unwrap_or(&[]);
        let size = usize::from_str_radix(std::str::from_utf8(hex).unwrap_or("x").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            loop {
                let l = src.read_line().await?;
                if l == b"\r\n" {
                    break;
                }
            }
            return Ok(());
        }
        discard_n(src, size).await?;
        let _ = src.read_line().await?; // trailing CRLF
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| format!("{}: {e}", path.display()))?
        .ok_or_else(|| format!("{}: no private key found", path.display()))
}

/// Dangerous verifier for `insecure_skip_verify`: skips certificate chain/name
/// checks but still verifies the handshake signature (so the channel is not
/// trivially forgeable). Only reachable when the operator opts in.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &str, action: HttpAction, status: Option<u16>) -> HttpRule {
        HttpRule { path: path.into(), action, status, body: String::new(), content_type: None }
    }

    #[test]
    fn request_path_extracts_target() {
        assert_eq!(request_path(b"GET /dns-query?x=1 HTTP/1.1\r\nHost: a\r\n\r\n"), "/dns-query?x=1");
        assert_eq!(request_path(b"POST / HTTP/1.1\r\n\r\n"), "/");
        assert_eq!(request_path(b"garbage"), "");
    }

    #[test]
    fn match_rule_prefix_and_catch_all() {
        let rules = vec![
            rule("/dns-query", HttpAction::Forward, None),
            rule("*", HttpAction::Respond, Some(404)),
        ];
        // prefix match wins first
        assert_eq!(match_rule(&rules, "/dns-query").unwrap().action, HttpAction::Forward);
        // subpath still matches the prefix
        assert_eq!(match_rule(&rules, "/dns-query/extra").unwrap().action, HttpAction::Forward);
        // anything else falls to the catch-all responder
        assert_eq!(match_rule(&rules, "/other").unwrap().action, HttpAction::Respond);
        // no rules => forward everything (None)
        assert!(match_rule(&[], "/anything").is_none());
    }

    #[test]
    fn direct_response_is_well_framed() {
        let r = HttpRule {
            path: "*".into(),
            action: HttpAction::Respond,
            status: Some(404),
            body: "nope\n".into(),
            content_type: Some("application/json".into()),
        };
        let out = String::from_utf8(direct_response(&r)).unwrap();
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"), "{out}");
        assert!(out.contains("Content-Type: application/json\r\n"), "{out}");
        assert!(out.contains("Content-Length: 5\r\n"), "{out}");
        assert!(out.ends_with("\r\n\r\nnope\n"), "{out}");
    }
}
