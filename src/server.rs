//! The data path: per-core `monoio` workers accepting connections and
//! forwarding them to backends after SNI routing.
//!
//! Sharding is `SO_REUSEPORT` + thread-per-core: one runtime per core, each
//! with its own accept sockets bound to the same addresses. The kernel spreads
//! connections (and UDP 4-tuples) across the reuseport group, so no work
//! stealing and no cross-core locking on the hot path. TCP passthrough uses
//! kernel **zero-copy splice** (`monoio::io::zero_copy`) — data never enters
//! user space.
//!
//! Reloadable state (routes/backends/ACLs/timeouts) lives behind an `ArcSwap`;
//! SIGHUP rebuilds it and swaps atomically, so live connections keep the state
//! they started with and new ones pick up the change without a restart.

use crate::acl::Acl;
use crate::backend::{ConnGuard, Pool};
use crate::config::validate::Level;
use crate::config::{Config, Mode, Proto, ProxyProtocol};
use crate::protocol::{proxy_protocol, quic, tls};
use crate::router;

use arc_swap::ArcSwap;
use monoio::buf::IoBuf;
use monoio::io::as_fd::{AsReadFd, AsWriteFd};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::udp::UdpSocket;
use monoio::net::{TcpListener, TcpStream};

use socket2::{Domain, Protocol as SockProto, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::metrics;

const UDP_DGRAM_MAX: usize = 2048;
const MAX_UDP_FLOWS: usize = 100_000;
const UDP_SWEEP_EVERY: u32 = 512;

/// State that can be swapped atomically on SIGHUP reload.
pub struct State {
    pub cfg: Config,
    pub pools: HashMap<String, Pool>,
    /// Compiled ACL per listener (indexed like `cfg.listeners`); `None` = no ACL.
    pub acls: Vec<Option<Acl>>,
}

/// Process-wide shared handle.
pub struct Shared {
    pub state: ArcSwap<State>,
    /// TLS contexts for terminate backends (built once; certs hot-reload via the
    /// cert watcher, not via SIGHUP).
    pub terminate: HashMap<String, crate::terminate::TerminateCtx>,
    pub started: Instant,
    config_path: PathBuf,
    /// Set on SIGTERM: accept loops stop taking new work and the process drains.
    shutting_down: AtomicBool,
    /// Active connection count per client IP, for `limits.max_conns_per_ip`.
    /// Contended only on connect/disconnect, never on the data path.
    conns_per_ip: Mutex<HashMap<IpAddr, u32>>,
}

/// Outcome of applying a new config through the admin API.
pub enum Applied {
    /// Reloadable state (routes/backends/timeouts/ACLs) was hot-swapped with no
    /// downtime; live connections are unaffected.
    HotSwapped,
    /// The change touches something baked in at process start (listener
    /// bind/proto, a terminate backend's TLS, `default_tls`, admin/metrics/log).
    /// The caller should [`fast_restart`] to apply it (drops connections).
    RestartRequired,
}

impl Shared {
    /// The config file this process was started with (writes target it).
    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    /// Apply an already-validated config. Hot-swaps when only reloadable state
    /// changed; otherwise reports that a restart is needed (without performing
    /// it, so the caller can respond first). Mirrors SIGHUP semantics.
    pub fn apply_config(&self, cfg: Config) -> Applied {
        if restart_sig(&self.state.load().cfg) != restart_sig(&cfg) {
            return Applied::RestartRequired;
        }
        self.state.store(Arc::new(build_state(cfg)));
        Applied::HotSwapped
    }
}

/// Signature of the config parts that are fixed for the process lifetime and
/// therefore can't be hot-swapped: listener bind/proto, every terminate backend
/// (baked into an immutable `TerminateCtx`), `default_tls`, and the admin /
/// metrics / log sections (bound or initialized once at startup). If this
/// signature is unchanged, a config edit is safe to apply live. `admin.token`
/// is `skip_serializing`, so a token-only change stays hot-swappable.
fn restart_sig(cfg: &Config) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for l in &cfg.listeners {
        let mut binds = l.bind.clone();
        binds.sort();
        let _ = write!(s, "L:{}:{:?}:{:?};", l.name, l.proto, binds);
    }
    // For terminate backends only the parts baked into the immutable
    // TerminateCtx matter (cert, re-encrypt, headers, http2, http_rules, mode) —
    // `servers`/`balance`/`health_check` are rebuilt into the pool on hot-swap,
    // so a server-list edit stays zero-downtime.
    for (name, b) in &cfg.backends {
        if matches!(b.mode, Mode::Terminate | Mode::TerminateTcp) {
            let _ = write!(
                s,
                "B:{name}:{:?}:{}:{}:{:?}:{}:{};",
                b.mode,
                serde_norway::to_string(&b.tls).unwrap_or_default(),
                serde_norway::to_string(&b.backend_tls).unwrap_or_default(),
                b.headers,
                b.http2,
                serde_norway::to_string(&b.http_rules).unwrap_or_default(),
            );
        }
    }
    let _ = write!(s, "DT:{:?};", serde_norway::to_string(&cfg.default_tls).ok());
    let _ = write!(s, "AD:{:?};", serde_norway::to_string(&cfg.admin).ok());
    let _ = write!(s, "MX:{:?};", serde_norway::to_string(&cfg.metrics).ok());
    let _ = write!(s, "LOG:{:?};", serde_norway::to_string(&cfg.log).ok());
    s
}

fn build_state(cfg: Config) -> State {
    let mut pools = HashMap::new();
    for (name, b) in &cfg.backends {
        if let Some(p) = Pool::from_backend(b) {
            pools.insert(name.clone(), p);
        }
    }
    let acls = cfg
        .listeners
        .iter()
        .map(|l| l.acl.as_ref().and_then(|a| Acl::compile(a).ok()))
        .collect();
    State { cfg, pools, acls }
}

/// Run the router until killed. Blocks the calling thread.
pub fn run(cfg: Config, config_path: PathBuf) -> io::Result<()> {
    let (terminate, cert_watch) = crate::terminate::TerminateCtx::build_all(&cfg);
    crate::terminate::spawn_cert_watcher(cert_watch);

    let shared = Arc::new(Shared {
        state: ArcSwap::new(Arc::new(build_state(cfg))),
        terminate,
        started: Instant::now(),
        config_path,
        shutting_down: AtomicBool::new(false),
        conns_per_ip: Mutex::new(HashMap::new()),
    });

    spawn_signal_thread(shared.clone());
    spawn_health_checker(shared.clone());

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    tracing::info!(
        listeners = shared.state.load().cfg.listeners.len(),
        cores,
        "sni-router starting"
    );

    let mut handles = Vec::new();
    for core in 0..cores {
        let shared = shared.clone();
        handles.push(std::thread::spawn(move || {
            pin_to_core(core);
            worker(core, shared);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// One thread-per-core worker: sets up every listener's accept sockets and runs
/// their loops on a dedicated monoio runtime.
fn worker(core: usize, shared: Arc<Shared>) {
    let mut rt = match monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .enable_timer()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(core, error = %e, "failed to build runtime");
            return;
        }
    };

    rt.block_on(async move {
        let mut tasks = Vec::new();

        // Admin API: a single control-plane listener, only on core 0. Served
        // over TLS when admin.tls / default_tls supplies a cert, else plaintext.
        if core == 0 {
            let snap = shared.state.load_full();
            if let Some(admin) = &snap.cfg.admin {
                let acceptor = match snap.cfg.effective_admin_tls() {
                    Some(tls) => match crate::terminate::build_acceptor(tls) {
                        Ok(a) => Some(a),
                        Err(e) => {
                            tracing::error!(error = %e, "admin TLS setup failed; API disabled");
                            None
                        }
                    },
                    None => None,
                };
                // With TLS misconfigured we skip the listener rather than expose
                // the write API in plaintext by accident.
                let tls_ok = snap.cfg.effective_admin_tls().is_none() || acceptor.is_some();
                if tls_ok {
                    match TcpListener::bind(admin.bind.as_str()) {
                        Ok(l) => {
                            let scheme = if acceptor.is_some() { "https" } else { "http" };
                            tracing::info!(bind = %admin.bind, scheme, "admin API listening");
                            let sh = shared.clone();
                            tasks.push(monoio::spawn(crate::admin::serve(l, sh, acceptor)));
                        }
                        Err(e) => {
                            tracing::error!(bind = %admin.bind, error = %e, "admin bind failed")
                        }
                    }
                }
            }
        }

        // Listener bind/proto structure is fixed for the process lifetime (SIGHUP
        // does not touch it), so it's safe to read once here.
        let snapshot = shared.state.load_full();
        for (idx, l) in snapshot.cfg.listeners.iter().enumerate() {
            for bind in &l.bind {
                let addr: SocketAddr = match bind.parse() {
                    Ok(a) => a,
                    Err(_) => continue, // validated already
                };
                match l.proto {
                    Proto::Tcp => match reuseport_tcp(addr) {
                        Ok(std_l) => match TcpListener::from_std(std_l) {
                            Ok(listener) => {
                                let sh = shared.clone();
                                tasks.push(monoio::spawn(tcp_accept_loop(listener, addr, idx, sh)));
                            }
                            Err(e) => tracing::error!(core, %addr, error = %e, "tcp from_std failed"),
                        },
                        Err(e) => tracing::error!(core, %addr, error = %e, "tcp bind failed"),
                    },
                    Proto::Udp => match reuseport_udp(addr) {
                        Ok(std_s) => match UdpSocket::from_std(std_s) {
                            Ok(sock) => {
                                let sh = shared.clone();
                                tasks.push(monoio::spawn(udp_worker(sock, addr, idx, sh)));
                            }
                            Err(e) => tracing::error!(core, %addr, error = %e, "udp from_std failed"),
                        },
                        Err(e) => tracing::error!(core, %addr, error = %e, "udp bind failed"),
                    },
                }
            }
        }
        // Accept loops never return; awaiting the first parks this task while
        // the runtime keeps driving all of them.
        for t in tasks {
            let _ = t.await;
        }
    });
}

async fn tcp_accept_loop(
    listener: TcpListener,
    local: SocketAddr,
    listener_idx: usize,
    shared: Arc<Shared>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Draining on SIGTERM: don't start new work, let the peer retry
                // elsewhere. Existing connections keep running until they finish.
                if shared.shutting_down.load(Ordering::Relaxed) {
                    drop(stream);
                    return;
                }
                let shared = shared.clone();
                monoio::spawn(async move {
                    let _ = handle_tcp(stream, peer, local, listener_idx, shared).await;
                });
            }
            Err(e) => {
                tracing::warn!(%local, error = %e, "accept failed");
                monoio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// RAII counter for `limits.max_conns_per_ip`. Absent when the limit is 0
/// (unlimited) so we don't touch the map at all in the common case.
struct IpLimit<'a> {
    map: &'a Mutex<HashMap<IpAddr, u32>>,
    ip: IpAddr,
}

impl<'a> IpLimit<'a> {
    /// Try to admit one more connection from `ip`. `None` = at the limit.
    /// Only called when `limit > 0` (the caller handles the unlimited case).
    fn acquire(map: &'a Mutex<HashMap<IpAddr, u32>>, ip: IpAddr, limit: usize) -> Option<Self> {
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(ip).or_insert(0);
        if (*n as usize) >= limit {
            return None;
        }
        *n += 1;
        Some(IpLimit { map, ip })
    }
}

impl Drop for IpLimit<'_> {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// RAII gauge for active connections (global + per-backend). Increments the
/// totals on creation, decrements the active gauges on drop, so early returns
/// and errors can't leak the count.
struct ActiveGuard {
    backend: Arc<metrics::Backend>,
}

impl ActiveGuard {
    fn new(backend: Arc<metrics::Backend>) -> Self {
        metrics::GLOBAL.conns_total.fetch_add(1, Ordering::Relaxed);
        metrics::GLOBAL.conns_active.fetch_add(1, Ordering::Relaxed);
        backend.conns_total.fetch_add(1, Ordering::Relaxed);
        backend.conns_active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard { backend }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        metrics::GLOBAL.conns_active.fetch_sub(1, Ordering::Relaxed);
        self.backend.conns_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Per-stream backend connector for the HTTP/2 gateway. Owns the shared state
/// (not a borrow) so each spawned stream task can hold and clone it. Looks the
/// pool up by name each time so a SIGHUP reload is picked up.
#[derive(Clone)]
struct Dialer {
    shared: Arc<Shared>,
    backend: String,
    connect_timeout: Duration,
}

impl crate::terminate::BackendDial for Dialer {
    async fn dial(&self) -> io::Result<TcpStream> {
        let st = self.shared.state.load_full();
        let pool = st
            .pools
            .get(&self.backend)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "backend removed on reload"))?;
        let mut tried: Vec<usize> = Vec::new();
        loop {
            let cand = pool.pick_candidate(&tried).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "no backend server available")
            })?;
            tried.push(cand);
            match monoio::time::timeout(self.connect_timeout, TcpStream::connect(pool.addr(cand)))
                .await
            {
                Ok(Ok(s)) => return Ok(s),
                _ => {
                    if pool.health_check() {
                        pool.set_healthy(cand, false);
                    }
                }
            }
        }
    }
}

async fn handle_tcp(
    mut client: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    listener_idx: usize,
    shared: Arc<Shared>,
) -> io::Result<()> {
    // load_full (owned Arc) rather than a Guard: this is held for the whole
    // (possibly long-lived) connection, and Guards are meant to be short.
    let st = shared.state.load_full();
    let acl = st.acls.get(listener_idx).and_then(|a| a.as_ref());

    // IP ACL: reject before we spend any effort reading the handshake.
    if let Some(acl) = acl {
        if !acl.ip_allowed(peer.ip()) {
            return Ok(());
        }
    }

    // Per-IP connection cap (limits.max_conns_per_ip; 0 = unlimited). Held for
    // the whole connection; the RAII guard releases the slot on drop.
    let limit = st.cfg.limits.max_conns_per_ip;
    let _ip_guard = if limit > 0 {
        match IpLimit::acquire(&shared.conns_per_ip, peer.ip(), limit) {
            Some(g) => Some(g),
            None => {
                metrics::GLOBAL.rate_limited.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%peer, limit, "connection rejected: per-IP limit reached");
                return Ok(());
            }
        }
    } else {
        None
    };

    let start = Instant::now();
    let max = st.cfg.limits.max_client_hello;
    let hs_timeout = Duration::from_secs(st.cfg.timeouts.handshake);

    // Buffer the ClientHello (across as many reads as it takes) and pull the SNI.
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let sni = loop {
        let tmp = vec![0u8; 4096];
        let (res, tmp) = match monoio::time::timeout(hs_timeout, client.read(tmp)).await {
            Ok(v) => v,
            Err(_) => return Ok(()), // handshake timeout (slowloris) — drop
        };
        let n = res?;
        if n == 0 {
            return Ok(()); // client closed before we could route
        }
        buf.extend_from_slice(&tmp[..n]);
        match tls::extract_sni(&buf, max) {
            tls::Sni::Found(s) => break s,
            tls::Sni::Absent | tls::Sni::NotClientHello => break String::new(),
            tls::Sni::Incomplete => {
                if buf.len() > max {
                    return Ok(()); // over cap without a complete ClientHello
                }
                continue;
            }
        }
    };

    // SNI ACL: now that we know the server name, enforce the name-based rules.
    if let Some(acl) = acl {
        if !acl.sni_allowed(&sni) {
            return Ok(());
        }
    }

    let routes = &st.cfg.listeners[listener_idx].routes;
    let backend_name = match router::pick(routes, &sni) {
        Some(b) => b,
        None => return Ok(()), // no matching route (and no catch-all) — drop
    };
    let pool = match st.pools.get(backend_name) {
        Some(p) => p,
        None => return Ok(()),
    };

    // redirect_https answers directly (301 / rules), no upstream connect.
    if pool.mode == Mode::RedirectHttps {
        let bm = metrics::backend(backend_name);
        metrics::GLOBAL.conns_total.fetch_add(1, Ordering::Relaxed);
        bm.conns_total.fetch_add(1, Ordering::Relaxed);
        let rules = st
            .cfg
            .backends
            .get(backend_name)
            .map(|b| b.http_rules.as_slice())
            .unwrap_or(&[]);
        let res = crate::redirect::handle(&buf, &mut client, rules).await;
        let down = *res.as_ref().unwrap_or(&0);
        metrics::GLOBAL.bytes_down.fetch_add(down, Ordering::Relaxed);
        bm.bytes_down.fetch_add(down, Ordering::Relaxed);
        if res.is_err() {
            metrics::GLOBAL.conn_errors.fetch_add(1, Ordering::Relaxed);
            bm.errors.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(
            target: "access",
            %peer,
            backend = backend_name,
            mode = "redirect",
            duration_ms = start.elapsed().as_millis() as u64,
            "connection closed"
        );
        return res.map(|_| ());
    }

    let bm = metrics::backend(backend_name);

    // Connect with retry across the pool: on failure try the next server
    // (healthy ones first). A live connect failure also marks the server down
    // when health checks are on, so the checker owns bringing it back.
    let connect_timeout = Duration::from_secs(st.cfg.timeouts.connect);
    let mut tried: Vec<usize> = Vec::new();
    let (idx, backend_tcp) = loop {
        let cand = match pool.pick_candidate(&tried) {
            Some(i) => i,
            None => {
                // Every server failed to connect — drop.
                metrics::GLOBAL.conn_errors.fetch_add(1, Ordering::Relaxed);
                bm.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(backend = backend_name, sni = sni_log(&sni), "all backend servers unreachable");
                return Ok(());
            }
        };
        tried.push(cand);
        match monoio::time::timeout(connect_timeout, TcpStream::connect(pool.addr(cand))).await {
            Ok(Ok(s)) => break (cand, s),
            _ => {
                if pool.health_check() {
                    pool.set_healthy(cand, false);
                }
            }
        }
    };
    let _guard = ConnGuard::new(pool, idx);
    let _active = ActiveGuard::new(bm.clone());

    if pool.mode == Mode::Terminate {
        // Dialer for the h2 gateway: reconnects per multiplexed stream (unused
        // on the HTTP/1.1 path, which uses the pre-connected `backend_tcp`).
        let dialer = Dialer {
            shared: shared.clone(),
            backend: backend_name.to_string(),
            connect_timeout,
        };
        let res = match shared.terminate.get(backend_name) {
            Some(ctx) => {
                crate::terminate::handle(buf, client, peer, &sni, backend_tcp, ctx, dialer).await
            }
            None => Ok(()), // TLS context failed to build at startup — drop
        };
        if res.is_err() {
            metrics::GLOBAL.conn_errors.fetch_add(1, Ordering::Relaxed);
            bm.errors.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(
            target: "access",
            %peer,
            sni = sni_log(&sni),
            backend = backend_name,
            mode = "terminate",
            duration_ms = start.elapsed().as_millis() as u64,
            "connection closed"
        );
        return res;
    }

    if pool.mode == Mode::TerminateTcp {
        // Terminate TLS, then raw-tunnel to the backend (DoT etc.). Optional
        // PROXY protocol is prepended to the backend stream.
        let proxy_header = match pool.proxy_protocol {
            ProxyProtocol::None => None,
            ProxyProtocol::V1 => Some(proxy_protocol::v1(peer, local)),
            ProxyProtocol::V2 => Some(proxy_protocol::v2(peer, local, false)),
        };
        let res = match shared.terminate.get(backend_name) {
            Some(ctx) => {
                crate::terminate::handle_raw(buf, client, backend_tcp, ctx, proxy_header).await
            }
            None => Ok((0, 0)), // TLS context failed to build at startup — drop
        };
        let (up, down) = *res.as_ref().unwrap_or(&(0, 0));
        metrics::GLOBAL.bytes_up.fetch_add(up, Ordering::Relaxed);
        metrics::GLOBAL.bytes_down.fetch_add(down, Ordering::Relaxed);
        bm.bytes_up.fetch_add(up, Ordering::Relaxed);
        bm.bytes_down.fetch_add(down, Ordering::Relaxed);
        if res.is_err() {
            metrics::GLOBAL.conn_errors.fetch_add(1, Ordering::Relaxed);
            bm.errors.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(
            target: "access",
            %peer,
            sni = sni_log(&sni),
            backend = backend_name,
            mode = "terminate_tcp",
            bytes_up = up,
            bytes_down = down,
            duration_ms = start.elapsed().as_millis() as u64,
            "connection closed"
        );
        return res.map(|_| ());
    }

    let mut upstream = backend_tcp;
    // PROXY protocol header carries the real client IP (the only way to pass it
    // in passthrough). `local` is what the client connected to on the router.
    let header = match pool.proxy_protocol {
        ProxyProtocol::None => None,
        ProxyProtocol::V1 => Some(proxy_protocol::v1(peer, local)),
        ProxyProtocol::V2 => Some(proxy_protocol::v2(peer, local, false)),
    };
    if let Some(h) = header {
        upstream.write_all(h).await.0?;
    }
    // Replay the buffered ClientHello verbatim, then hand both directions to the
    // kernel via splice. Those replayed bytes count toward client->backend too.
    let hello_len = buf.len() as u64;
    upstream.write_all(buf).await.0?;

    let (cr, cw) = client.into_split();
    let (ur, uw) = upstream.into_split();
    let c2u = monoio::spawn(splice_dir(cr, uw)); // client -> backend
    let down = splice_dir(ur, cw).await; // backend -> client
    let up = c2u.await + hello_len;

    metrics::GLOBAL.bytes_up.fetch_add(up, Ordering::Relaxed);
    metrics::GLOBAL.bytes_down.fetch_add(down, Ordering::Relaxed);
    bm.bytes_up.fetch_add(up, Ordering::Relaxed);
    bm.bytes_down.fetch_add(down, Ordering::Relaxed);
    tracing::info!(
        target: "access",
        %peer,
        sni = sni_log(&sni),
        backend = backend_name,
        mode = "passthrough",
        bytes_up = up,
        bytes_down = down,
        duration_ms = start.elapsed().as_millis() as u64,
        "connection closed"
    );
    Ok(())
}

/// Render an empty SNI as `-` for access logs.
fn sni_log(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

/// Zero-copy one direction with `splice` until EOF, then close the write side.
/// Returns the number of bytes transferred.
async fn splice_dir<R, W>(mut r: R, mut w: W) -> u64
where
    R: AsReadFd,
    W: AsWriteFd + AsyncWriteRent,
{
    let n = monoio::io::zero_copy(&mut r, &mut w).await.unwrap_or(0);
    let _ = w.shutdown().await;
    n as u64
}

// ---------------------------------------------------------------------------
// SIGHUP reload + health checks
// ---------------------------------------------------------------------------

/// Rebuild reloadable state from the config file. Invalid configs and
/// bind/proto changes are rejected; the running config keeps serving.
fn reload(shared: &Shared) {
    let cfg = match crate::config::load(&shared.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "reload: failed to parse config; keeping running config");
            return;
        }
    };
    let diags = crate::config::validate::validate(&cfg);
    if diags.iter().any(|d| d.level == Level::Error) {
        tracing::error!("reload rejected: new config has errors; keeping running config");
        for d in diags.iter().filter(|d| d.level == Level::Error) {
            tracing::error!(path = %d.path, "{}", d.message);
        }
        return;
    }
    if !same_listeners(&shared.state.load().cfg, &cfg) {
        // Accept sockets are bound once per worker at startup and can't be added
        // or removed inside a running monoio runtime, so applying listener
        // changes means a fresh bind. Re-exec ourselves: fast (no drain), picks
        // up the new listeners, keeps the same PID for systemd. Config is already
        // validated above, so the new image will start cleanly.
        tracing::warn!(
            "reload: listener bind/proto changed — fast-restarting to apply \
             (active connections will drop)"
        );
        fast_restart();
    }
    shared.state.store(Arc::new(build_state(cfg)));
    tracing::info!("configuration reloaded");
}

/// Re-exec the current binary in place (same PID, same args/env). Sockets close
/// on exec (CLOEXEC), dropping all connections, then the fresh process rebinds —
/// a fast restart without the graceful drain. Only returns on failure.
#[cfg(unix)]
pub fn fast_restart() -> ! {
    use std::os::unix::process::CommandExt;
    // The caller may be a worker thread pinned to a single core (e.g. the admin
    // API runs on core 0). exec() inherits the CPU affinity mask, which would
    // leave the re-exec'd process pinned to one core (available_parallelism → 1,
    // one worker). Reset affinity to all online CPUs first so the fresh process
    // spins up its full thread-per-core set again.
    #[cfg(target_os = "linux")]
    unsafe {
        let n = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if n > 0 {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            for i in 0..(n as usize).min(libc::CPU_SETSIZE as usize) {
                libc::CPU_SET(i, &mut set);
            }
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let err = std::process::Command::new(exe).args(args).exec();
    tracing::error!(error = %err, "fast restart (re-exec) failed; exiting");
    std::process::exit(1);
}

#[cfg(not(unix))]
pub fn fast_restart() -> ! {
    std::process::exit(1);
}

/// SIGUSR1 handler: validate the on-disk config, then fast-restart if it's good.
/// A broken config keeps the running process alive (same guarantee as SIGHUP).
#[cfg(unix)]
fn fast_restart_checked(shared: &Shared) {
    match crate::config::load(&shared.config_path) {
        Ok(cfg) => {
            let diags = crate::config::validate::validate(&cfg);
            if diags.iter().any(|d| d.level == Level::Error) {
                tracing::error!("fast restart aborted: config has errors; keeping running config");
                return;
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "fast restart aborted: cannot parse config");
            return;
        }
    }
    tracing::warn!("SIGUSR1: fast-restarting (dropping all connections)");
    fast_restart();
}

/// Do the two configs have the same listener bind/proto structure? (SIGHUP can
/// only change routes/backends/timeouts/acls, not the accept sockets.)
fn same_listeners(a: &Config, b: &Config) -> bool {
    a.listeners.len() == b.listeners.len()
        && a.listeners.iter().zip(&b.listeners).all(|(x, y)| {
            x.proto == y.proto && {
                let mut xb = x.bind.clone();
                let mut yb = y.bind.clone();
                xb.sort();
                yb.sort();
                xb == yb
            }
        })
}

#[cfg(unix)]
fn spawn_signal_thread(shared: Arc<Shared>) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1};
    std::thread::spawn(move || {
        let mut signals =
            match signal_hook::iterator::Signals::new([SIGHUP, SIGTERM, SIGINT, SIGUSR1]) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "signal handler setup failed");
                    return;
                }
            };
        for sig in signals.forever() {
            match sig {
                SIGHUP => reload(&shared),
                SIGUSR1 => fast_restart_checked(&shared),
                SIGTERM | SIGINT => graceful_shutdown(&shared),
                _ => {}
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_signal_thread(_shared: Arc<Shared>) {}

/// Stop accepting new connections, wait for active ones to finish (up to
/// `timeouts.drain`), then exit. New accepts are refused via `shutting_down`;
/// this loop watches the active-connection gauge and exits when it hits zero or
/// the drain deadline passes. Diverges (exits the process).
#[cfg(unix)]
fn graceful_shutdown(shared: &Shared) -> ! {
    let drain = shared.state.load().cfg.timeouts.drain.max(1);
    shared.shutting_down.store(true, Ordering::Relaxed);
    tracing::info!(drain_secs = drain, "shutdown signal received; draining connections");
    let deadline = Instant::now() + Duration::from_secs(drain);
    loop {
        let active = metrics::GLOBAL.conns_active.load(Ordering::Relaxed);
        if active == 0 {
            tracing::info!("drain complete; exiting");
            break;
        }
        if Instant::now() >= deadline {
            tracing::warn!(active, "drain timeout reached; exiting with connections still active");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::process::exit(0);
}

/// Background TCP-connect health probing for backends with `health_check: true`.
/// Runs on a dedicated system thread with blocking connects — off the io_uring
/// data path.
fn spawn_health_checker(shared: Arc<Shared>) {
    std::thread::spawn(move || loop {
        let (interval, connect_to) = {
            let st = shared.state.load();
            (st.cfg.timeouts.health_interval.max(1), st.cfg.timeouts.connect.max(1))
        };
        std::thread::sleep(Duration::from_secs(interval));
        let st = shared.state.load_full();
        for pool in st.pools.values() {
            if !pool.health_check() {
                continue;
            }
            for i in 0..pool.server_count() {
                let up = std::net::TcpStream::connect_timeout(
                    &pool.addr(i),
                    Duration::from_secs(connect_to),
                )
                .is_ok();
                pool.set_healthy(i, up);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// UDP / QUIC passthrough
// ---------------------------------------------------------------------------

struct Flow {
    upstream: Rc<UdpSocket>,
    backend: SocketAddr,
    routed: bool,
    reasm: quic::CryptoReasm,
    pending: Vec<Vec<u8>>,
    last: Instant,
}

/// One UDP accept socket. QUIC 4-tuples are pinned to this socket by the
/// reuseport hash, so a per-socket (single-thread) flow table is race-free.
///
/// Known limitation — QUIC connection migration: flows are keyed by the client
/// 4-tuple. When a client migrates networks it switches to a fresh Connection
/// ID delivered inside encrypted 1-RTT NEW_CONNECTION_ID frames, which an L4
/// passthrough proxy (that never has the server's keys) cannot decrypt or
/// correlate. Correct handling requires cooperative CID routing on the backend
/// (QUIC-LB, RFC 9000 §5.1 / draft-ietf-quic-load-balancers); until then a
/// migrated connection lands as a new flow and re-handshakes.
async fn udp_worker(sock: UdpSocket, local: SocketAddr, listener_idx: usize, shared: Arc<Shared>) {
    let sock = Rc::new(sock);
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut ticks: u32 = 0;

    loop {
        let buf = vec![0u8; UDP_DGRAM_MAX];
        let (res, buf) = sock.recv_from(buf).await;
        let (n, peer) = match res {
            Ok(v) => v,
            Err(_) => continue,
        };
        metrics::GLOBAL.udp_datagrams.fetch_add(1, Ordering::Relaxed);
        let dgram = &buf[..n];

        let st = shared.state.load_full();
        let idle = Duration::from_secs(st.cfg.timeouts.idle);

        ticks = ticks.wrapping_add(1);
        if ticks % UDP_SWEEP_EVERY == 0 {
            flows.retain(|_, f| f.last.elapsed() < idle);
        }

        if let Some(flow) = flows.get_mut(&peer) {
            flow.last = Instant::now();
            if flow.routed {
                let _ = flow.upstream.send_to(dgram.to_vec(), flow.backend).await.0;
                continue;
            }
            // Still collecting the ClientHello for this flow.
            flow.pending.push(dgram.to_vec());
            if let Some(sni) = advance_quic(flow, dgram) {
                route_udp(&mut flows, peer, sni, local, listener_idx, &shared, &sock).await;
            }
            continue;
        }

        // New flow.
        if let Some(acl) = st.acls.get(listener_idx).and_then(|a| a.as_ref()) {
            if !acl.ip_allowed(peer.ip()) {
                continue; // IP not permitted on this listener
            }
        }
        if flows.len() >= MAX_UDP_FLOWS {
            continue; // shed load rather than grow unbounded
        }
        let mut flow = Flow {
            upstream: Rc::new(dummy_udp()), // replaced on routing
            backend: local, // placeholder, set on routing
            routed: false,
            reasm: quic::CryptoReasm::new(),
            pending: vec![dgram.to_vec()],
            last: Instant::now(),
        };
        let decided = advance_quic(&mut flow, dgram);
        flows.insert(peer, flow);
        if let Some(sni) = decided {
            route_udp(&mut flows, peer, sni, local, listener_idx, &shared, &sock).await;
        }
    }
}

/// Feed a datagram into the flow's QUIC reassembly. Returns `Some(sni)` once we
/// can decide a route (`""` = route via catch-all), `None` to keep waiting.
fn advance_quic(flow: &mut Flow, dgram: &[u8]) -> Option<String> {
    match quic::scan(dgram) {
        quic::Scan::Crypto(frags) => {
            for (off, data) in frags {
                flow.reasm.push(off, &data);
            }
            match flow.reasm.try_sni() {
                tls::Sni::Found(s) => Some(s),
                tls::Sni::Absent | tls::Sni::NotClientHello => Some(String::new()),
                tls::Sni::Incomplete => None,
            }
        }
        // Not a QUIC v1 Initial at all — treat as plain UDP, route via catch-all.
        quic::Scan::NotInitial => Some(String::new()),
        // Fake/undecryptable Initial (Zapret fooling): ignore, wait for the real one.
        quic::Scan::Fake => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn route_udp(
    flows: &mut HashMap<SocketAddr, Flow>,
    peer: SocketAddr,
    sni: String,
    local: SocketAddr,
    listener_idx: usize,
    shared: &Arc<Shared>,
    sock: &Rc<UdpSocket>,
) {
    let st = shared.state.load_full();

    // SNI ACL for the QUIC listener.
    if let Some(acl) = st.acls.get(listener_idx).and_then(|a| a.as_ref()) {
        if !acl.sni_allowed(&sni) {
            flows.remove(&peer);
            return;
        }
    }

    let routes = &st.cfg.listeners[listener_idx].routes;
    let backend_name = match router::pick(routes, &sni) {
        Some(n) => n,
        None => {
            flows.remove(&peer);
            return;
        }
    };
    // terminate not valid for udp — treat as no route.
    let pool = match st.pools.get(backend_name).filter(|p| p.mode != Mode::Terminate) {
        Some(p) => p,
        None => {
            flows.remove(&peer);
            return;
        }
    };
    let bm = metrics::backend(backend_name);
    let idx = pool.pick();
    let addr = pool.addr(idx);

    let up = match connect_udp(addr) {
        Ok(u) => Rc::new(u),
        Err(e) => {
            tracing::warn!(%addr, error = %e, "udp backend connect failed");
            bm.errors.fetch_add(1, Ordering::Relaxed);
            flows.remove(&peer);
            return;
        }
    };
    metrics::GLOBAL.udp_flows_total.fetch_add(1, Ordering::Relaxed);
    bm.conns_total.fetch_add(1, Ordering::Relaxed);
    tracing::info!(target: "access", %peer, sni = sni_log(&sni), backend = backend_name, mode = "quic", "flow routed");

    // Optional PROXY protocol: sent once as its own leading datagram so the QUIC
    // payload that follows stays byte-exact.
    // ponytail: separate-datagram framing; if a backend wants it prepended to
    // the first datagram instead, that's a one-line change here.
    match pool.proxy_protocol {
        ProxyProtocol::None => {}
        ProxyProtocol::V1 => {
            let _ = up.send_to(proxy_protocol::v1(peer, local), addr).await.0;
        }
        ProxyProtocol::V2 => {
            let _ = up.send_to(proxy_protocol::v2(peer, local, true), addr).await.0;
        }
    }

    let idle = Duration::from_secs(st.cfg.timeouts.idle);
    let Some(flow) = flows.get_mut(&peer) else { return };
    flow.upstream = up.clone();
    flow.backend = addr;
    flow.routed = true;
    let pending = std::mem::take(&mut flow.pending);
    for d in pending {
        let _ = up.send_to(d, addr).await.0;
    }

    // Pump backend -> client for this flow.
    let sock = sock.clone();
    monoio::spawn(async move {
        let mut buf = vec![0u8; UDP_DGRAM_MAX];
        loop {
            let (res, b) = match monoio::time::timeout(idle, up.recv_from(buf)).await {
                Ok(v) => v,
                Err(_) => break,
            };
            buf = b;
            let n = match res {
                Ok((0, _)) => break,
                Ok((n, _)) => n,
                Err(_) => break,
            };
            let (sres, slice) = sock.send_to(buf.slice(..n), peer).await;
            buf = slice.into_inner();
            if sres.is_err() {
                break;
            }
        }
    });
}

/// A fresh unconnected UDP socket for talking to a backend. Left unconnected on
/// purpose: we address the backend with `send_to`, and a `send_to` with an
/// explicit destination on a *connected* UDP socket can return `EISCONN`.
fn connect_udp(backend: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if backend.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let std_sock = std::net::UdpSocket::bind(bind)?;
    UdpSocket::from_std(std_sock)
}

fn dummy_udp() -> UdpSocket {
    // Placeholder before a flow is routed; never sent on.
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    UdpSocket::from_std(s).expect("from_std loopback")
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------

fn reuseport_tcp(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let sock = new_reuseport_socket(addr, Type::STREAM, SockProto::TCP)?;
    sock.listen(1024)?;
    Ok(sock.into())
}

fn reuseport_udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let sock = new_reuseport_socket(addr, Type::DGRAM, SockProto::UDP)?;
    Ok(sock.into())
}

fn new_reuseport_socket(addr: SocketAddr, ty: Type, proto: SockProto) -> io::Result<Socket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, ty, Some(proto))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    // Never rely on implicit dual-stack: bind v4 and v6 explicitly, force
    // v6-only on IPv6 sockets so behavior is identical across environments
    // (bindv6only default varies, especially inside snap/containers).
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

/// Pin the current thread to `core` (best effort; ignored on failure).
fn pin_to_core(core: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core % libc::CPU_SETSIZE as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core;
}
