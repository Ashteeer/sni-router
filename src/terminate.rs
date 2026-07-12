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
use bytes::Bytes;
use http::{Request, Response};
use monoio_http::h2::server as h2server;
use monoio_http::h2::{RecvStream, SendStream};
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
    /// Whether `h2` ALPN is advertised and terminated (terminate mode only).
    http2: bool,
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
        // HTTP terminate advertises http/1.1 (plus h2 when enabled); the raw
        // (terminate_tcp) tunnel leaves ALPN unset so clients negotiating e.g.
        // "dot" still connect.
        if b.mode == crate::config::Mode::Terminate {
            server.alpn_protocols = if b.http2 {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            };
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
            http2: b.http2 && b.mode == crate::config::Mode::Terminate,
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
/// `dialer` supplies fresh backend connections for the HTTP/2 gateway (which
/// needs one per multiplexed stream); it is unused on the HTTP/1.1 path.
pub async fn handle<D: BackendDial>(
    prefix: Vec<u8>,
    client: TcpStream,
    peer: SocketAddr,
    sni: &str,
    backend: TcpStream,
    ctx: &TerminateCtx,
    dialer: D,
) -> io::Result<()> {
    let io = PrefixedReadIo::new(client, Cursor::new(prefix));
    let tls = ctx
        .acceptor
        .accept(io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls accept: {e}")))?;

    // ALPN h2 (advertised only when the backend opted in): run the h2->HTTP/1.1
    // gateway. The pre-connected `backend` is unused here — h2 multiplexes, so
    // each stream dials its own backend connection.
    if ctx.http2 && tls.alpn_protocol().as_deref() == Some(&b"h2"[..]) {
        drop(backend);
        let rules = Arc::new(ctx.http_rules.clone());
        return h2_gateway(tls, dialer, ctx.headers, rules, peer).await;
    }

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

        // Path rules: a matching `respond` or `redirect` rule answers the client
        // directly (after draining its request body) without touching the
        // backend. Non-matching requests (or `forward` rules) fall through.
        if let Some(rule) = match_rule(rules, request_path(&head)) {
            if rule.action != HttpAction::Forward {
                skip_body(&mut client, &head).await?;
                let resp = synthetic_response(rule, request_host(&head), request_path(&head), true);
                client.write_all(resp).await?;
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
pub(crate) fn request_path(head: &[u8]) -> &str {
    let line = match head.split(|&b| b == b'\r' || b == b'\n').next() {
        Some(l) => l,
        None => return "",
    };
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.split_whitespace().nth(1))
        .unwrap_or("")
}

/// The `Host` header value from an HTTP head (empty if absent).
pub(crate) fn request_host(head: &[u8]) -> &str {
    std::str::from_utf8(head)
        .ok()
        .and_then(|text| {
            text.split("\r\n").skip(1).find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.trim().eq_ignore_ascii_case("host").then(|| v.trim())
            })
        })
        .unwrap_or("")
}

/// First rule whose path prefix (or `*`) matches; `None` = forward as usual.
pub(crate) fn match_rule<'a>(rules: &'a [HttpRule], path: &str) -> Option<&'a HttpRule> {
    rules
        .iter()
        .find(|r| r.path == "*" || path.starts_with(r.path.as_str()))
}

/// Resolve a redirect `to` target: the literal `https` means "same host+path
/// over https"; anything else is used verbatim (an absolute URL).
pub(crate) fn redirect_location(to: &str, host: &str, path: &str) -> String {
    if to == "https" {
        format!("https://{host}{path}")
    } else {
        to.to_string()
    }
}

/// Render a `respond` or `redirect` rule into an HTTP/1.1 response. `host`/`path`
/// feed the dynamic `https` redirect target. `keep_alive` picks the `Connection`
/// header: terminate pipelines (true); the plaintext responder answers once and
/// closes (false). Shared with `redirect.rs`.
pub(crate) fn synthetic_response(
    rule: &HttpRule,
    host: &str,
    path: &str,
    keep_alive: bool,
) -> Vec<u8> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    if rule.action == HttpAction::Redirect {
        let status = rule.status.unwrap_or(301);
        let reason = reason_phrase(status);
        let location = redirect_location(rule.to.as_deref().unwrap_or("https"), host, path);
        return format!(
            "HTTP/1.1 {status} {reason}\r\nLocation: {location}\r\n\
             Content-Length: 0\r\nConnection: {conn}\r\n\r\n"
        )
        .into_bytes();
    }
    // respond
    let status = rule.status.unwrap_or(200);
    let reason = reason_phrase(status);
    let ctype = rule.content_type.as_deref().unwrap_or("text/plain");
    let body = rule.body.as_bytes();
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\n\
         Content-Length: {}\r\nConnection: {conn}\r\n\r\n",
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
// HTTP/2 termination (h2 -> HTTP/1.1 gateway)
// ---------------------------------------------------------------------------

/// Supplies fresh backend TCP connections for the HTTP/2 gateway — one per
/// multiplexed stream. Implemented by `server` (which owns pool/retry/health).
pub trait BackendDial: Clone + 'static {
    fn dial(&self) -> impl std::future::Future<Output = io::Result<TcpStream>>;
}

/// Drive an h2 connection: accept streams and gateway each to HTTP/1.1. Each
/// stream runs as its own task; the accept loop keeps driving the connection
/// (that is what flushes the spawned streams' frames), per the monoio-http
/// server pattern.
///
/// Limitations (documented): backends are spoken to over HTTP/1.1 plaintext
/// (no re-encrypt), and server push / trailers are not forwarded.
async fn h2_gateway<T, D>(
    tls: T,
    dialer: D,
    headers: Headers,
    rules: Arc<Vec<HttpRule>>,
    peer: SocketAddr,
) -> io::Result<()>
where
    T: AsyncReadRent + AsyncWriteRent + Unpin + 'static,
    D: BackendDial,
{
    let mut conn = h2server::handshake(tls)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {e}")))?;
    while let Some(result) = conn.accept().await {
        let (request, respond) = match result {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dialer = dialer.clone();
        let rules = rules.clone();
        monoio::spawn(async move {
            if let Err(e) = h2_stream(request, respond, dialer, headers, rules, peer).await {
                tracing::debug!(error = %e, "h2 stream error");
            }
        });
    }
    Ok(())
}

/// Request-body framing chosen when forwarding to the HTTP/1.1 backend.
enum ReqBody {
    None,
    Length(usize),
    Chunked,
}

async fn h2_stream<D: BackendDial>(
    mut request: Request<RecvStream>,
    mut respond: h2server::SendResponse<Bytes>,
    dialer: D,
    headers: Headers,
    rules: Arc<Vec<HttpRule>>,
    peer: SocketAddr,
) -> io::Result<()> {
    let path = request.uri().path().to_string();

    // Path rule: `respond`/`redirect` answer without touching a backend.
    if let Some(rule) = match_rule(&rules, &path) {
        if rule.action != HttpAction::Forward {
            drain_h2_body(request.body_mut()).await;
            let host = request.uri().authority().map(|a| a.as_str()).unwrap_or("");
            let (resp, body) = h2_synthetic(rule, host, &path)?;
            let mut send = respond.send_response(resp, body.is_empty()).map_err(h2_io)?;
            if !body.is_empty() {
                send.send_data(body, true).map_err(h2_io)?;
            }
            return Ok(());
        }
    }

    // Forward to an HTTP/1.1 backend (fresh connection per stream).
    let framing = req_body_framing(&request);
    let backend = dialer.dial().await?;
    let mut backend = Buf::new(backend);
    let head = build_h1_request_head(&request, peer, &headers, &framing);
    backend.write_all(head).await?;
    forward_h2_body_to_h1(request.body_mut(), &mut backend, &framing).await?;

    // Response back to the client as h2.
    let rhead = match backend.read_head().await? {
        Some(h) => h,
        None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "backend closed early")),
    };
    let (resp, body) = h1_head_to_h2_response(&rhead)?;
    let end = matches!(body, Body::None);
    let mut send = respond.send_response(resp, end).map_err(h2_io)?;
    match body {
        Body::None => {}
        Body::Length(n) => h1_len_to_h2(&mut backend, &mut send, n).await?,
        Body::Chunked => h1_chunked_to_h2(&mut backend, &mut send).await?,
        Body::UntilEof => h1_eof_to_h2(&mut backend, &mut send).await?,
    }
    Ok(())
}

/// Build an h2 `respond`/`redirect` response (`Response<()>` head + body bytes).
fn h2_synthetic(rule: &HttpRule, host: &str, path: &str) -> io::Result<(Response<()>, Bytes)> {
    let build_err = |e: http::Error| io::Error::new(io::ErrorKind::Other, e.to_string());
    if rule.action == HttpAction::Redirect {
        let status = rule.status.unwrap_or(301);
        let location = redirect_location(rule.to.as_deref().unwrap_or("https"), host, path);
        let resp = Response::builder()
            .status(status)
            .header("location", location)
            .body(())
            .map_err(build_err)?;
        return Ok((resp, Bytes::new()));
    }
    let status = rule.status.unwrap_or(200);
    let ctype = rule.content_type.as_deref().unwrap_or("text/plain");
    let resp = Response::builder()
        .status(status)
        .header("content-type", ctype)
        .body(())
        .map_err(build_err)?;
    Ok((resp, Bytes::from(rule.body.clone().into_bytes())))
}

fn req_body_framing(request: &Request<RecvStream>) -> ReqBody {
    if request.body().is_end_stream() {
        return ReqBody::None;
    }
    match request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        Some(n) => ReqBody::Length(n),
        None => ReqBody::Chunked,
    }
}

/// Build the HTTP/1.1 request head from the h2 request, injecting the configured
/// forwarding headers (mirrors `rewrite_request` but reads an `http::HeaderMap`).
fn build_h1_request_head(
    request: &Request<RecvStream>,
    peer: SocketAddr,
    cfg: &Headers,
    framing: &ReqBody,
) -> Vec<u8> {
    let method = request.method().as_str();
    let target = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{method} {target} HTTP/1.1\r\n").as_bytes());

    // Host from :authority (h2) or an explicit host header.
    let host = request
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());

    let mut existing_xff: Option<String> = None;
    for (name, value) in request.headers() {
        let n = name.as_str();
        if matches!(
            n,
            "host" | "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                | "te" | "upgrade" | "content-length"
        ) {
            continue; // hop-by-hop / framing headers are re-derived
        }
        if cfg.x_real_ip && n == "x-real-ip" {
            continue;
        }
        if cfg.x_forwarded_proto && n == "x-forwarded-proto" {
            continue;
        }
        if cfg.x_forwarded_for && n == "x-forwarded-for" {
            existing_xff = value.to_str().ok().map(|s| s.to_string());
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    match framing {
        ReqBody::None => {}
        ReqBody::Length(n) => out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes()),
        ReqBody::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
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
    out
}

async fn drain_h2_body(body: &mut RecvStream) {
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(data) => {
                let _ = body.flow_control().release_capacity(data.len());
            }
            Err(_) => break,
        }
    }
}

/// Forward the h2 request body to the HTTP/1.1 backend using `framing`.
async fn forward_h2_body_to_h1<S>(
    body: &mut RecvStream,
    backend: &mut Buf<S>,
    framing: &ReqBody,
) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    match framing {
        ReqBody::None => Ok(()),
        ReqBody::Length(_) => {
            while let Some(chunk) = body.data().await {
                let data = chunk.map_err(h2_io)?;
                let _ = body.flow_control().release_capacity(data.len());
                backend.write_all(data.to_vec()).await?;
            }
            Ok(())
        }
        ReqBody::Chunked => {
            while let Some(chunk) = body.data().await {
                let data = chunk.map_err(h2_io)?;
                let _ = body.flow_control().release_capacity(data.len());
                if data.is_empty() {
                    continue;
                }
                backend.write_all(format!("{:x}\r\n", data.len()).into_bytes()).await?;
                backend.write_all(data.to_vec()).await?;
                backend.write_all(b"\r\n".to_vec()).await?;
            }
            backend.write_all(b"0\r\n\r\n".to_vec()).await?;
            Ok(())
        }
    }
}

/// Parse the HTTP/1.1 response head into an h2 `Response<()>` plus body framing.
fn h1_head_to_h2_response(head: &[u8]) -> io::Result<(Response<()>, Body)> {
    let status = status_of(head).unwrap_or(502);
    let mut builder = Response::builder().status(status);
    let text = String::from_utf8_lossy(head);
    for (i, line) in text.split("\r\n").enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let n = name.trim().to_ascii_lowercase();
            if matches!(
                n.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                    | "upgrade" | "content-length"
            ) {
                continue; // h2 forbids hop-by-hop / connection-specific headers
            }
            builder = builder.header(n, value.trim());
        }
    }
    let framing = body_len(head, false, false)?;
    let resp = builder
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok((resp, framing))
}

async fn h1_len_to_h2<S>(
    backend: &mut Buf<S>,
    send: &mut SendStream<Bytes>,
    mut n: usize,
) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    if n == 0 {
        return h2_send(send, Bytes::new(), true).await;
    }
    while n > 0 {
        if backend.data.is_empty() && !backend.fill().await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in response body"));
        }
        let take = n.min(backend.data.len());
        let chunk: Vec<u8> = backend.data.drain(..take).collect();
        n -= take;
        h2_send(send, Bytes::from(chunk), n == 0).await?;
    }
    Ok(())
}

async fn h1_chunked_to_h2<S>(backend: &mut Buf<S>, send: &mut SendStream<Bytes>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    loop {
        let line = backend.read_line().await?;
        let hex = line.split(|&b| b == b';' || b == b'\r').next().unwrap_or(&[]);
        let mut size = usize::from_str_radix(std::str::from_utf8(hex).unwrap_or("x").trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            loop {
                let l = backend.read_line().await?;
                if l == b"\r\n" {
                    break;
                }
            }
            return h2_send(send, Bytes::new(), true).await;
        }
        while size > 0 {
            if backend.data.is_empty() && !backend.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in chunk"));
            }
            let take = size.min(backend.data.len());
            let chunk: Vec<u8> = backend.data.drain(..take).collect();
            size -= take;
            h2_send(send, Bytes::from(chunk), false).await?;
        }
        let _ = backend.read_line().await?; // trailing CRLF
    }
}

async fn h1_eof_to_h2<S>(backend: &mut Buf<S>, send: &mut SendStream<Bytes>) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
{
    loop {
        if !backend.data.is_empty() {
            let chunk = std::mem::take(&mut backend.data);
            h2_send(send, Bytes::from(chunk), false).await?;
        }
        if !backend.fill().await? {
            return h2_send(send, Bytes::new(), true).await;
        }
    }
}

/// Send `data` on an h2 stream, respecting flow-control capacity. `end` marks
/// the last frame.
async fn h2_send(send: &mut SendStream<Bytes>, data: Bytes, end: bool) -> io::Result<()> {
    if data.is_empty() {
        if end {
            send.send_data(Bytes::new(), true).map_err(h2_io)?;
        }
        return Ok(());
    }
    let mut data = data;
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = await_capacity(send).await?;
        if cap == 0 {
            continue;
        }
        let take = cap.min(data.len());
        let chunk = data.split_to(take);
        let last = end && data.is_empty();
        send.send_data(chunk, last).map_err(h2_io)?;
    }
    Ok(())
}

async fn await_capacity(send: &mut SendStream<Bytes>) -> io::Result<usize> {
    std::future::poll_fn(|cx| send.poll_capacity(cx))
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "h2 stream reset"))?
        .map_err(h2_io)
}

fn h2_io(e: monoio_http::h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("h2: {e}"))
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
        HttpRule { path: path.into(), action, status, body: String::new(), content_type: None, to: None }
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
    fn respond_is_well_framed() {
        let r = HttpRule {
            path: "*".into(),
            action: HttpAction::Respond,
            status: Some(404),
            body: "nope\n".into(),
            content_type: Some("application/json".into()),
            to: None,
        };
        let out = String::from_utf8(synthetic_response(&r, "h", "/p", true)).unwrap();
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"), "{out}");
        assert!(out.contains("Content-Type: application/json\r\n"), "{out}");
        assert!(out.contains("Content-Length: 5\r\n"), "{out}");
        assert!(out.ends_with("\r\n\r\nnope\n"), "{out}");
    }

    #[test]
    fn redirect_to_https_uses_host_and_path() {
        let r = HttpRule {
            path: "*".into(),
            action: HttpAction::Redirect,
            status: None,
            body: String::new(),
            content_type: None,
            to: Some("https".into()),
        };
        let out = String::from_utf8(synthetic_response(&r, "example.com", "/a?b=1", false)).unwrap();
        assert!(out.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{out}");
        assert!(out.contains("Location: https://example.com/a?b=1\r\n"), "{out}");
    }

    #[test]
    fn redirect_to_literal_url() {
        let r = HttpRule {
            path: "*".into(),
            action: HttpAction::Redirect,
            status: Some(302),
            body: String::new(),
            content_type: None,
            to: Some("https://new.example.com/".into()),
        };
        let out = String::from_utf8(synthetic_response(&r, "old", "/x", false)).unwrap();
        assert!(out.starts_with("HTTP/1.1 302 Found\r\n"), "{out}");
        assert!(out.contains("Location: https://new.example.com/\r\n"), "{out}");
    }
}
