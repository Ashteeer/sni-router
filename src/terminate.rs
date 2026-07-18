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
    /// Read by `server` to decide whether to defer the backend connect.
    pub http2: bool,
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
    pub fn build_all(cfg: &crate::config::Config) -> (HashMapCtx, Vec<CertWatch>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut out = std::collections::HashMap::new();
        let mut watch = Vec::new();
        for (name, b) in &cfg.backends {
            if !matches!(b.mode, crate::config::Mode::Terminate | crate::config::Mode::TerminateTcp) {
                continue;
            }
            match Self::build_one(b, cfg.effective_tls(b), &provider) {
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

    fn build_one(
        b: &Backend,
        tls: Option<&crate::config::Tls>,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, String> {
        let tls = tls.ok_or("terminate backend has no tls and no default_tls is set")?;
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

/// Build a plain TLS acceptor from a cert/key pair, for the admin API. Unlike
/// terminate backends this has no hot-reload watcher — a renewed admin cert is
/// picked up on the next restart, which is fine for a low-traffic control plane.
pub fn build_acceptor(tls: &crate::config::Tls) -> Result<TlsAcceptor, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = load_certs(&tls.cert)?;
    let key = load_key(&tls.key)?;
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

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
    ctx: &TerminateCtx,
    dialer: D,
    idle: Duration,
) -> io::Result<()> {
    let io = PrefixedReadIo::new(client, Cursor::new(prefix));
    // Bound the TLS handshake: a client that sent the ClientHello (already read
    // under the handshake timeout) but then stalls mid-handshake must not hang
    // here forever.
    let tls = match monoio::time::timeout(idle, ctx.acceptor.accept(io)).await {
        Ok(r) => r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls accept: {e}")))?,
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "tls handshake timeout")),
    };

    // ALPN h2 (advertised only when the backend opted in): run the h2->HTTP/1.1
    // gateway. h2 multiplexes, so each stream dials its own backend connection.
    if ctx.http2 && tls.alpn_protocol().as_deref() == Some(&b"h2"[..]) {
        let rules = Arc::new(ctx.http_rules.clone());
        return h2_gateway(tls, dialer, ctx.headers, rules, peer, idle).await;
    }

    // HTTP/1.1: the request loop obtains a backend connection per request through
    // the channel — pooled plaintext, or a held TLS stream for re-encrypt — so
    // the client connection survives any single backend connection ending.
    let client = Buf::new(tls, Some(idle));
    match &ctx.backend {
        None => {
            let chan = PlainChan { dialer, idle };
            http_forward(client, chan, peer, &ctx.headers, &ctx.http_rules).await
        }
        Some(bc) => {
            let name = bc.sni.clone().unwrap_or_else(|| sni.to_string());
            let server = ServerName::try_from(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid backend SNI"))?;
            let chan = TlsChan { dialer, connector: bc.connector.clone(), server, idle };
            http_forward(client, chan, peer, &ctx.headers, &ctx.http_rules).await
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
    idle: Duration,
) -> io::Result<(u64, u64)> {
    let io = PrefixedReadIo::new(client, Cursor::new(prefix));
    // Bound only the handshake; the tunnel that follows is deliberately
    // long-lived (DoT keeps a connection open) and is reaped by TCP keepalive,
    // not an idle read deadline that would kill a quiet-but-healthy session.
    let tls = match monoio::time::timeout(idle, ctx.acceptor.accept(io)).await {
        Ok(r) => r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls accept: {e}")))?,
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "tls handshake timeout")),
    };

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
    /// Reusable read buffer, cycled through `read` the same way splice does, so
    /// the streaming body path allocates nothing per chunk. Lazily created.
    scratch: Option<Vec<u8>>,
    /// Per-read idle deadline. Bounds every user-space read on this stream, so a
    /// client that finishes the TLS handshake and then dribbles a request head
    /// or body (slowloris) can't pin the connection — and its pre-connected
    /// backend — indefinitely. `None` disables it (e.g. long-lived tunnels).
    read_timeout: Option<Duration>,
}

impl<S: AsyncReadRent + AsyncWriteRent> Buf<S> {
    fn new(s: S, read_timeout: Option<Duration>) -> Self {
        Buf { s, data: Vec::new(), scratch: None, read_timeout }
    }

    /// Recover the stream. Only meaningful once `data` is empty — leftover bytes
    /// mean the caller stopped mid-message and the stream can't be reused.
    fn into_inner(self) -> S {
        self.s
    }

    /// Nothing buffered: the last message ended exactly where the reads did.
    fn is_drained(&self) -> bool {
        self.data.is_empty()
    }

    /// Read more bytes into the buffer. Returns false on EOF. Reuses `scratch`
    /// (no per-read allocation) and honours `read_timeout`.
    async fn fill(&mut self) -> io::Result<bool> {
        let scratch = self.scratch.take().unwrap_or_else(|| vec![0u8; IO_CHUNK]);
        let (r, scratch) = read_timed(&mut self.s, scratch, self.read_timeout).await;
        let n = r?;
        if n > 0 {
            self.data.extend_from_slice(&scratch[..n]);
        }
        self.scratch = Some(scratch);
        Ok(n > 0)
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
///
/// After emptying whatever `src` already read past the head, the remainder is
/// streamed straight from `src`'s socket into `dst`'s through one reusable
/// buffer — no per-chunk allocation and no second copy via `src.data` (which the
/// old `drain(..).collect()` paid on every chunk). Any bytes read past `n` (a
/// pipelined next request) are stashed back into `src.data`.
async fn forward_n<S, D>(src: &mut Buf<S>, dst: &mut Buf<D>, mut n: usize) -> io::Result<()>
where
    S: AsyncReadRent + AsyncWriteRent,
    D: AsyncReadRent + AsyncWriteRent,
{
    // 1. Drain bytes already buffered past the head (bounded, one-time).
    while n > 0 && !src.data.is_empty() {
        let take = n.min(src.data.len());
        let chunk: Vec<u8> = src.data.drain(..take).collect();
        n -= chunk.len();
        dst.write_all(chunk).await?;
    }
    if n == 0 {
        return Ok(());
    }
    // 2. Stream the rest with a reusable buffer.
    let mut scratch = src.scratch.take().unwrap_or_else(|| vec![0u8; IO_CHUNK]);
    while n > 0 {
        let (r, b) = read_timed(&mut src.s, scratch, src.read_timeout).await;
        scratch = b;
        let got = r?;
        if got == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in body"));
        }
        let take = n.min(got);
        let (w, slice) = dst.s.write_all(scratch.slice(..take)).await;
        scratch = slice.into_inner();
        w?;
        n -= take;
        if got > take {
            // Over-read into the next message: keep it for the next read_head.
            src.data.extend_from_slice(&scratch[take..got]);
        }
    }
    src.scratch = Some(scratch);
    Ok(())
}

/// Read into `buf`, honouring an optional idle deadline. On timeout the in-flight
/// buffer is lost (the caller is about to drop the connection), so an empty vec
/// comes back with the error.
async fn read_timed<S: AsyncReadRent>(
    s: &mut S,
    buf: Vec<u8>,
    timeout: Option<Duration>,
) -> (io::Result<usize>, Vec<u8>) {
    match timeout {
        Some(t) => match monoio::time::timeout(t, s.read(buf)).await {
            Ok(v) => v,
            Err(_) => (
                Err(io::Error::new(io::ErrorKind::TimedOut, "idle read timeout")),
                Vec::new(),
            ),
        },
        None => s.read(buf).await,
    }
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
    // Flush the buffered leftover, then cycle one reusable buffer to EOF.
    if !src.data.is_empty() {
        let chunk = std::mem::take(&mut src.data);
        dst.write_all(chunk).await?;
    }
    let mut scratch = src.scratch.take().unwrap_or_else(|| vec![0u8; IO_CHUNK]);
    loop {
        let (r, b) = read_timed(&mut src.s, scratch, src.read_timeout).await;
        scratch = b;
        let got = r?;
        if got == 0 {
            src.scratch = Some(scratch);
            return Ok(());
        }
        let (w, slice) = dst.s.write_all(scratch.slice(..got)).await;
        scratch = slice.into_inner();
        w?;
    }
}

/// Source of backend connections for the HTTP/1.1 terminate loop. It abstracts
/// the two backend flavors so the loop itself never has to care which it is:
///
/// - **plaintext** ([`PlainChan`]): pooled `TcpStream`s — `dial` takes a live one
///   from the shared idle pool (with a peek that drops a connection the backend
///   already closed) or opens a new one; `put` returns it to the pool for reuse
///   by *other* client connections.
/// - **re-encrypt** ([`TlsChan`]): one TLS stream held for this client
///   connection's lifetime (a TLS stream can't go into the raw pool); `put`
///   keeps it for the next request.
///
/// The whole point: a backend connection dying — idle keep-alive close, EOF, an
/// error — is confined to the backend hop. The loop gets a fresh one and the
/// **client** connection keeps living by the router's own timeouts, exactly like
/// nginx / HAProxy / Envoy. (Before this, the backend was pinned to the client
/// for its whole life, so the backend's keep-alive close tore down the client.)
trait BackendChan {
    type Stream: AsyncReadRent + AsyncWriteRent + Split + 'static;
    /// A ready backend connection: a reused live one when available, else new.
    fn dial(&self) -> impl std::future::Future<Output = io::Result<Buf<Self::Stream>>>;
    /// Offer a used, cleanly-drained, keep-alive connection back. `Some` = hold
    /// it for the next request on this client connection; `None` = it was handed
    /// off (e.g. to the shared pool), so `dial` again next time.
    fn put(&self, b: Buf<Self::Stream>) -> Option<Buf<Self::Stream>>;
}

/// Plaintext backend: pooled `TcpStream`s via the shared idle pool.
struct PlainChan<D: BackendDial> {
    dialer: D,
    idle: Duration,
}

impl<D: BackendDial> BackendChan for PlainChan<D> {
    type Stream = TcpStream;
    async fn dial(&self) -> io::Result<Buf<TcpStream>> {
        Ok(Buf::new(self.dialer.dial().await?, Some(self.idle)))
    }
    fn put(&self, b: Buf<TcpStream>) -> Option<Buf<TcpStream>> {
        // Back to the shared idle pool for cross-connection reuse; re-dial next
        // request (`dial`'s liveness peek is what makes that safe after an idle).
        self.dialer.release(b.into_inner());
        None
    }
}

/// Re-encrypt backend: a TLS stream, held for the client connection's lifetime.
struct TlsChan<D: BackendDial> {
    dialer: D,
    connector: TlsConnector,
    server: ServerName<'static>,
    idle: Duration,
}

impl<D: BackendDial> BackendChan for TlsChan<D> {
    type Stream = monoio_rustls::ClientTlsStream<TcpStream>;
    async fn dial(&self) -> io::Result<Buf<Self::Stream>> {
        // A re-encrypt backend never returns raw sockets to the pool, so the
        // pool for its address is always empty and this is a fresh TCP connect
        // underneath — no chance of TLS-handshaking over a pooled plaintext one.
        let tcp = self.dialer.dial().await?;
        let tls = self
            .connector
            .connect(self.server.clone(), tcp)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("backend tls: {e}")))?;
        Ok(Buf::new(tls, Some(self.idle)))
    }
    fn put(&self, b: Buf<Self::Stream>) -> Option<Buf<Self::Stream>> {
        Some(b) // hold across requests; TLS streams don't go in the raw pool
    }
}

/// Why a request couldn't be forwarded — decides whether the client body still
/// needs draining before the 502 (so the client stream stays aligned).
#[derive(PartialEq)]
enum FwdFail {
    /// Failed before the request body was consumed (no backend / head write).
    BeforeBody,
    /// The body (if any) was already consumed, so the client is aligned.
    Consumed,
}

/// The HTTP/1.1 terminate request loop. Each request gets a backend connection
/// from `chan` (pooled or held); the **client** connection outlives any single
/// backend connection and is bounded only by the router's own idle timeout.
async fn http_forward<C, Ch>(
    mut client: Buf<C>,
    chan: Ch,
    peer: SocketAddr,
    headers: &Headers,
    rules: &[HttpRule],
) -> io::Result<()>
where
    C: AsyncReadRent + AsyncWriteRent + Split + 'static,
    Ch: BackendChan,
{
    // Backend connection carried between requests (TLS holds it; plaintext keeps
    // `None` and re-dials from the pool each request).
    let mut held: Option<Buf<Ch::Stream>> = None;

    loop {
        // --- request head from the client (bounded by the client idle timeout) ---
        let head = match client.read_head().await? {
            Some(h) => h,
            None => return Ok(()), // client closed its keep-alive — normal end
        };

        // Path rules answer directly, no backend.
        if let Some(rule) = match_rule(rules, request_path(&head)) {
            if rule.action != HttpAction::Forward {
                skip_body(&mut client, &head).await?;
                let resp = synthetic_response(rule, request_host(&head), request_path(&head), true);
                client.write_all(resp).await?;
                continue;
            }
        }

        let (rewritten, method) = rewrite_request(&head, peer, headers)?;
        let framing = body_len(&head, true, false)?;
        let has_body = !matches!(framing, Body::None);
        let is_head = method.eq_ignore_ascii_case("HEAD");
        // Retry a failed forward on a fresh connection only when the request can
        // be replayed verbatim: idempotent method AND no body to re-stream.
        let can_retry = is_idempotent(&method) && !has_body;

        // Acquire a backend, send the request, read the response head — retrying
        // once on a fresh connection if a reused one turned out to be dead.
        let mut attempt = 0u8;
        let outcome: Result<(Vec<u8>, Buf<Ch::Stream>), FwdFail> = loop {
            let mut backend = match held.take() {
                Some(b) => b,
                None => match chan.dial().await {
                    Ok(b) => b,
                    Err(_) => break Err(FwdFail::BeforeBody),
                },
            };
            // Send the request head.
            if backend.write_all(rewritten.clone()).await.is_err() {
                drop(backend);
                if attempt == 0 && can_retry {
                    attempt += 1;
                    continue;
                }
                break Err(FwdFail::BeforeBody); // nothing consumed from the client yet
            }
            // Stream the request body — this consumes it from the client, which
            // realigns the client stream at the next request boundary.
            if has_body {
                let r = match framing {
                    Body::Length(n) => forward_n(&mut client, &mut backend, n).await,
                    Body::Chunked => forward_chunked(&mut client, &mut backend).await,
                    Body::UntilEof => forward_to_eof(&mut client, &mut backend).await,
                    Body::None => Ok(()),
                };
                if let Err(e) = r {
                    // A client read or a backend write failed mid-body: the client
                    // stream is now unaligned and unrecoverable — end it.
                    return Err(e);
                }
            }
            // Read the response head.
            match backend.read_head().await {
                Ok(Some(rhead)) => break Ok((rhead, backend)),
                _ => {
                    drop(backend);
                    if attempt == 0 && can_retry {
                        attempt += 1;
                        continue;
                    }
                    break Err(FwdFail::Consumed); // body (if any) already consumed
                }
            }
        };

        let (rhead, mut backend) = match outcome {
            Ok(v) => v,
            Err(fail) => {
                // Keep the client connection alive: answer 502 so a dead or
                // unreachable backend never takes the client down with it.
                if fail == FwdFail::BeforeBody && has_body {
                    skip_body(&mut client, &head).await?; // drain to realign
                }
                client.write_all(bad_gateway()).await?;
                continue;
            }
        };

        // --- response back to the client ---
        let status = status_of(&rhead);
        let body = body_len(&rhead, false, is_head)?;
        // 101 Switching Protocols: framing ends here. Forward the head verbatim
        // (Connection/Upgrade must survive) and hand off to a raw tunnel.
        if status == Some(101) {
            client.write_all(rhead).await?;
            return upgrade_tunnel(client, backend).await;
        }
        // The backend's own keep-alive intent decides whether we reuse *its*
        // connection — but it must never govern the client hop. `UntilEof`
        // responses are delimited by the backend closing, so the client hop
        // closes too; everything else stays keep-alive on the client side.
        let backend_keep = h1_keeps_alive(&rhead);
        let client_close = matches!(body, Body::UntilEof);
        client.write_all(rewrite_response(&rhead, client_close)).await?;
        match body {
            Body::None => {}
            Body::Length(n) => forward_n(&mut backend, &mut client, n).await?,
            Body::Chunked => forward_chunked(&mut backend, &mut client).await?,
            Body::UntilEof => {
                forward_to_eof(&mut backend, &mut client).await?;
                return Ok(()); // response delimited by backend close → client closes too
            }
        }
        // Reuse the backend connection only from a provably clean boundary.
        held = if backend_keep && backend.is_drained() {
            chan.put(backend)
        } else {
            None // Connection: close or leftover bytes → drop it, re-dial next time
        };
    }
}

/// Idempotent HTTP methods (RFC 9110 §9.2.2) — safe to replay on a fresh backend
/// connection when a reused one was already dead.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "DELETE" | "PUT"
    )
}

/// A 502 that keeps the client connection alive (so one bad backend request
/// doesn't drop a client that could still make good ones).
fn bad_gateway() -> Vec<u8> {
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".to_vec()
}

/// Rewrite a response head for the client hop: strip the backend's connection-
/// management headers (they describe the router↔backend hop, not client↔router)
/// and set our own `Connection`. This is what decouples the client's keep-alive
/// from the backend's — a backend `Connection: close` no longer closes the client.
fn rewrite_response(head: &[u8], client_close: bool) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut out = Vec::with_capacity(head.len() + 24);
    out.extend_from_slice(status_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        // Hop-by-hop / connection-management headers are re-derived, not relayed.
        if matches!(name.as_str(), "connection" | "keep-alive" | "proxy-connection") {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(if client_close {
        b"Connection: close\r\n"
    } else {
        b"Connection: keep-alive\r\n"
    });
    out.extend_from_slice(b"\r\n");
    out
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
    let Buf { s: cs, data: cleft, .. } = client;
    let Buf { s: bs, data: bleft, .. } = backend;
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

/// Supplies backend TCP connections for the HTTP/2 gateway. Implemented by
/// `server`, which owns the pool/retry/health logic and the idle-connection
/// cache — `dial` may hand back a parked keep-alive connection instead of
/// opening a new one.
pub trait BackendDial: Clone + 'static {
    fn dial(&self) -> impl std::future::Future<Output = io::Result<TcpStream>>;
    /// Offer a connection back for reuse. Only call this on a clean message
    /// boundary: response fully consumed, keep-alive agreed, nothing buffered.
    fn release(&self, s: TcpStream);
}

/// Drive an h2 connection: accept streams and gateway each to HTTP/1.1. Each
/// stream runs as its own task; the accept loop keeps driving the connection
/// (that is what flushes the spawned streams' frames), per the monoio-http
/// server pattern.
///
/// Limitations (documented): backends are spoken to over HTTP/1.1 plaintext
/// (no re-encrypt), and server push / trailers are not forwarded.
/// Cap on concurrent h2 streams per connection, advertised in SETTINGS. Without
/// it one client can open a near-unbounded number of streams — each of which
/// dials a backend — and amplify a single TCP connection into thousands of
/// backend connections (the Rapid Reset / CVE-2023-44487 shape), sailing past
/// `max_conns_per_ip` (which counts TCP connections, not streams).
const H2_MAX_CONCURRENT_STREAMS: u32 = 128;

async fn h2_gateway<T, D>(
    tls: T,
    dialer: D,
    headers: Headers,
    rules: Arc<Vec<HttpRule>>,
    peer: SocketAddr,
    idle: Duration,
) -> io::Result<()>
where
    T: AsyncReadRent + AsyncWriteRent + Unpin + 'static,
    D: BackendDial,
{
    let handshake = h2server::Builder::new()
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .handshake(tls);
    let mut conn = match monoio::time::timeout(idle, handshake).await {
        Ok(r) => r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {e}")))?,
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "h2 handshake timeout")),
    };
    while let Some(result) = conn.accept().await {
        let (request, respond) = match result {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dialer = dialer.clone();
        let rules = rules.clone();
        monoio::spawn(async move {
            if let Err(e) = h2_stream(request, respond, dialer, headers, rules, peer, idle).await {
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
    idle: Duration,
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

    // Forward to an HTTP/1.1 backend. `dial` may return a pooled keep-alive
    // connection, so this is often handshake-free.
    let framing = req_body_framing(&request);
    let backend = dialer.dial().await?;
    let mut backend = Buf::new(backend, Some(idle));
    let head = build_h1_request_head(&request, peer, &headers, &framing);
    backend.write_all(head).await?;
    forward_h2_body_to_h1(request.body_mut(), &mut backend, &framing).await?;

    // Response back to the client as h2.
    let rhead = match backend.read_head().await? {
        Some(h) => h,
        None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "backend closed early")),
    };
    let keep_alive = h1_keeps_alive(&rhead);
    let (resp, body) = h1_head_to_h2_response(&rhead)?;
    let end = matches!(body, Body::None);
    let mut send = respond.send_response(resp, end).map_err(h2_io)?;
    match body {
        Body::None => {}
        Body::Length(n) => h1_len_to_h2(&mut backend, &mut send, n).await?,
        Body::Chunked => h1_chunked_to_h2(&mut backend, &mut send).await?,
        // "Until EOF" *is* the framing: the response ends when the connection
        // does, so there is nothing left to reuse.
        Body::UntilEof => {
            h1_eof_to_h2(&mut backend, &mut send).await?;
            return Ok(());
        }
    }
    // Reuse only from a provably clean boundary. `is_drained` is the guard that
    // matters: leftover bytes would become the head of the next request's
    // response — a response-splitting bug, not just a slow path.
    if keep_alive && backend.is_drained() {
        dialer.release(backend.into_inner());
    }
    Ok(())
}

/// May this HTTP/1.1 response's connection be reused for another request?
///
/// Defaults follow RFC 9112 §9.3: HTTP/1.1 persists, HTTP/1.0 does not, and an
/// explicit `Connection:` token overrides the default either way. Anything we
/// can't parse is treated as "don't reuse" — a wrong `false` costs a
/// handshake, a wrong `true` corrupts the next response on that socket.
fn h1_keeps_alive(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let http11 = lines.next().is_some_and(|l| l.starts_with("HTTP/1.1"));
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("connection") {
            continue;
        }
        let v = value.to_ascii_lowercase();
        let mut tokens = v.split(',').map(str::trim);
        if tokens.clone().any(|t| t == "close") {
            return false;
        }
        if tokens.any(|t| t == "keep-alive") {
            return true;
        }
    }
    http11
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

    /// Guards connection reuse in the h2 gateway: a wrong `true` here would
    /// park a connection the backend is closing, and the next request on it
    /// would read a truncated or foreign response.
    #[test]
    fn keep_alive_follows_version_and_connection_header() {
        let cases: &[(&str, bool)] = &[
            // HTTP/1.1 persists by default.
            ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true),
            // ...unless told otherwise.
            ("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", false),
            ("HTTP/1.1 200 OK\r\nconnection: CLOSE\r\n\r\n", false),
            // Multi-token and padded values.
            ("HTTP/1.1 200 OK\r\nConnection: keep-alive, foo\r\n\r\n", true),
            ("HTTP/1.1 200 OK\r\nConnection: foo,  close \r\n\r\n", false),
            // HTTP/1.0 closes by default...
            ("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", false),
            // ...and opts in explicitly.
            ("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n", true),
            // Unparseable status line: refuse to reuse.
            ("garbage\r\n\r\n", false),
        ];
        for (head, want) in cases {
            assert_eq!(h1_keeps_alive(head.as_bytes()), *want, "head: {head:?}");
        }
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
