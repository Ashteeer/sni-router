//! `mode: terminate` — the router terminates the client's TLS itself, injects
//! `X-Real-IP` / `X-Forwarded-*` headers, and forwards to the backend as
//! HTTP/1.1 (optionally re-encrypted with TLS + mTLS).
//!
//! TCP only; QUIC/HTTP3 termination is out of scope. HTTP/1.1 is handled in a
//! sequential request/response loop (which also copes with pipelining, since
//! bodies are precisely framed). ponytail: no `Upgrade`/WebSocket in terminate
//! yet — those need full-duplex splitting; add when a use case appears.

use crate::config::{Backend, Headers};
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
            if b.mode != crate::config::Mode::Terminate {
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
                Err(e) => eprintln!("backend {name}: terminate TLS setup failed: {e}"),
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
        server.alpn_protocols = vec![b"http/1.1".to_vec()];

        let backend = match &b.backend_tls {
            None => None,
            Some(bt) => {
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
        };

        Ok(TerminateCtx {
            acceptor: TlsAcceptor::from(Arc::new(server)),
            backend,
            headers: b.headers,
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
                            eprintln!("sni-router: reloaded certificate {}", w.cert.display());
                        }
                        Err(e) => {
                            eprintln!("sni-router: cert reload {} failed: {e}", w.cert.display())
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
        None => http_forward(Buf::new(tls), Buf::new(backend), peer, &ctx.headers).await,
        Some(bc) => {
            let name = bc.sni.clone().unwrap_or_else(|| sni.to_string());
            let domain = ServerName::try_from(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid backend SNI"))?;
            let btls = bc
                .connector
                .connect(domain, backend)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("backend tls: {e}")))?;
            http_forward(Buf::new(tls), Buf::new(btls), peer, &ctx.headers).await
        }
    }
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

async fn tunnel_copy<R, W>(mut r: R, mut w: W)
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    let mut buf = vec![0u8; IO_CHUNK];
    loop {
        let (res, b) = r.read(buf).await;
        buf = b;
        let n = match res {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let (wres, slice) = w.write_all(buf.slice(..n)).await;
        buf = slice.into_inner();
        if wres.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
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
