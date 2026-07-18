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
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::metrics;

const UDP_DGRAM_MAX: usize = 2048;
const MAX_UDP_FLOWS: usize = 100_000;
/// How often to reap idle UDP flows. Time-based, not packet-counted: a flood of
/// datagrams must not force a full-table scan on every Nth packet, and a quiet
/// table must still be swept. This is only the backstop for flows that never got
/// a backend reply — the backend->client pump already reaps on its own idle.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

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
    /// Contended only on connect/disconnect, never on the data path — and
    /// sharded by IP so accepts from different clients don't serialize on one
    /// lock across all cores. Only touched when the limit is enabled.
    conns_per_ip: [Mutex<HashMap<IpAddr, u32>>; IP_SHARDS],
}

/// Number of `conns_per_ip` shards. A power of two so the hash maps cheaply.
const IP_SHARDS: usize = 32;

/// Which `conns_per_ip` shard an address belongs to.
fn ip_shard(ip: IpAddr) -> usize {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    (h.finish() as usize) & (IP_SHARDS - 1)
}

/// Outcome of applying a new config through the admin API.
pub enum Applied {
    /// Reloadable state (routes/backends/timeouts/ACLs) was hot-swapped with no
    /// downtime; live connections are unaffected.
    HotSwapped,
    /// The change touches something baked in at process start (listener
    /// bind/proto, a terminate backend's TLS, `default_tls`, api/log).
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
/// (baked into an immutable `TerminateCtx`), `default_tls`, and the api / log
/// sections (bound or initialized once at startup). If this signature is
/// unchanged, a config edit is safe to apply live. `api.token` is
/// `skip_serializing`, so a token-only change stays hot-swappable.
fn restart_sig(cfg: &Config) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for l in &cfg.listeners {
        let mut binds = l.bind.clone();
        binds.sort();
        let _ = write!(
            s,
            "L:{}:{:?}:{:?}:{}:{}:{};",
            l.name,
            l.proto,
            binds,
            l.fast_open,
            l.fast_open_qlen(),
            l.backlog()
        );
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
    let _ = write!(s, "API:{:?};", serde_norway::to_string(&cfg.api).ok());
    let _ = write!(s, "LOG:{:?};", serde_norway::to_string(&cfg.log).ok());
    s
}

fn build_state(cfg: Config) -> State {
    let mut pools = HashMap::new();
    for (name, b) in &cfg.backends {
        if let Some(p) = Pool::from_backend(name, b) {
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
    metrics::init();
    let (terminate, cert_watch) = crate::terminate::TerminateCtx::build_all(&cfg);
    crate::terminate::spawn_cert_watcher(cert_watch);

    let shared = Arc::new(Shared {
        state: ArcSwap::new(Arc::new(build_state(cfg))),
        terminate,
        started: Instant::now(),
        config_path,
        shutting_down: AtomicBool::new(false),
        conns_per_ip: std::array::from_fn(|_| Mutex::new(HashMap::new())),
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

        // Management + metrics API: a single control-plane listener, only on
        // core 0. Served over TLS when api.tls / default_tls supplies a cert,
        // else plaintext.
        if core == 0 {
            let snap = shared.state.load_full();
            if let Some(api) = &snap.cfg.api {
                // With TLS misconfigured we skip the listener rather than expose
                // the write API in plaintext by accident.
                let acceptor = match snap.cfg.effective_api_tls() {
                    Some(tls) => match crate::terminate::build_acceptor(tls) {
                        Ok(a) => Ok(Some(a)),
                        Err(e) => Err(e),
                    },
                    None => Ok(None),
                };
                match acceptor {
                    Err(e) => tracing::error!(error = %e, "api TLS setup failed; API disabled"),
                    Ok(acceptor) => match TcpListener::bind(api.bind.as_str()) {
                        Ok(l) => {
                            let scheme = if acceptor.is_some() { "https" } else { "http" };
                            tracing::info!(bind = %api.bind, scheme, "management API listening");
                            let sh = shared.clone();
                            tasks.push(monoio::spawn(crate::admin::serve(l, sh, acceptor)));
                        }
                        Err(e) => {
                            tracing::error!(bind = %api.bind, error = %e, "api bind failed")
                        }
                    },
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
                let defer_accept = snapshot.cfg.timeouts.handshake as u32;
                match l.proto {
                    Proto::Tcp => match reuseport_tcp(addr, l, defer_accept) {
                        Ok(std_l) => {
                            // One report per address, not per reuseport worker.
                            if core == 0 {
                                log_listener(addr, l, std::os::fd::AsRawFd::as_raw_fd(&std_l));
                            }
                            match TcpListener::from_std(std_l) {
                                Ok(listener) => {
                                    let sh = shared.clone();
                                    tasks.push(monoio::spawn(tcp_accept_loop(
                                        listener, addr, idx, sh,
                                    )));
                                }
                                Err(e) => {
                                    tracing::error!(core, %addr, error = %e, "tcp from_std failed")
                                }
                            }
                        }
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

/// Socket options for every TCP stream on the data path — client-facing and
/// backend-facing alike, so a forwarded byte meets the same settings on both
/// legs.
///
/// `TCP_NODELAY` is unconditional: a router must never sit on a small write
/// waiting for more data to batch. Nagle holds a sub-MSS segment until the
/// previous one is ACKed, which against the peer's delayed ACK stalls a
/// forwarded packet for tens of milliseconds — the exact profile of what we
/// carry (VPN, DoT, WebSocket, request/response). There is no workload here
/// where batching beats latency: we forward someone else's already-framed
/// bytes, so the sender's own batching decisions are the ones that count.
///
/// Failures are ignored: a socket that rejects an option still works, just
/// without the tuning, and dropping a live connection over it would be worse.
fn tune_stream(s: &TcpStream, keepalive: Option<Duration>) {
    let _ = s.set_nodelay(true);
    if let Some(idle) = keepalive {
        // Interval/retries stay at the system defaults — one knob to reason
        // about, and the system's values are already tuned per host.
        let _ = s.set_tcp_keepalive(Some(idle), None, None);
    }
}

// ---------------------------------------------------------------------------
// Idle backend connections for the HTTP/2 gateway
// ---------------------------------------------------------------------------

// Idle keep-alive connections to backends, keyed by server address.
//
// Thread-local by necessity and by design: monoio is thread-per-core and a
// `TcpStream` is bound to the runtime that created it (not `Send`), so each
// core keeps its own. No locking on the hot path as a result.
//
// Only the h2 gateway uses this. HTTP/1.1 terminate holds one backend
// connection for the whole client connection, and passthrough hands the socket
// to splice — neither has a connection to hand back between requests.
thread_local! {
    static IDLE_BACKENDS: RefCell<HashMap<SocketAddr, Vec<(TcpStream, Instant)>>> =
        RefCell::new(HashMap::new());
    static IDLE_PUTS: Cell<u32> = const { Cell::new(0) };
}

/// Cap per server address, per core. Bounds file descriptors when a burst of
/// concurrent streams opens more connections than steady state needs.
const POOL_MAX_IDLE: usize = 32;
/// How long an unused connection may sit before we stop trusting it. Backends
/// close idle keep-alives on their own schedule (nginx defaults to 75s, Apache
/// to 5s), so this is a cheap upper bound — `reusable` is what actually catches
/// a closed one.
const POOL_IDLE_TTL: Duration = Duration::from_secs(30);
/// Sweep every N releases, so a backend removed from the config doesn't leave
/// its idle connections parked forever.
const POOL_SWEEP_EVERY: u32 = 256;

/// Is this idle connection still usable?
///
/// A backend may close a keep-alive connection at any moment, and we would
/// normally only discover that by writing into a socket that is already gone.
/// A non-blocking peek asks now, without consuming anything: `0` means the peer
/// closed, readable bytes on a connection we believe is idle mean the stream is
/// out of sync (a late body, a pipelined response), and `EAGAIN` — nothing to
/// read — is the one healthy answer.
///
/// This narrows the race to the microseconds between the peek and the write; it
/// cannot close it. A backend that hangs up in that window fails the stream.
/// ponytail: no retry-on-fresh-connection — that needs request-idempotence
/// rules to be safe, and this window is orders of magnitude rarer than the
/// closed-idle-connection case the peek already handles.
fn reusable(s: &TcpStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut b = [0u8; 1];
    // SAFETY: fd is owned by `s` and outlives the call; the buffer is a valid
    // 1-byte destination. MSG_DONTWAIT keeps it from blocking the worker.
    let n = unsafe {
        libc::recv(s.as_raw_fd(), b.as_mut_ptr().cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT)
    };
    n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
}

/// Take a live idle connection to `addr`, if one is parked on this core.
fn take_idle(addr: SocketAddr) -> Option<TcpStream> {
    IDLE_BACKENDS.with(|p| {
        let mut map = p.borrow_mut();
        let v = map.get_mut(&addr)?;
        // Newest first: it has had the least time to go stale.
        while let Some((s, since)) = v.pop() {
            if since.elapsed() < POOL_IDLE_TTL && reusable(&s) {
                metrics::GLOBAL.pool_hits.fetch_add(1, Ordering::Relaxed);
                return Some(s);
            }
        }
        None
    })
}

/// Park a connection for reuse. The caller must have left it on a clean message
/// boundary (response fully read, no `Connection: close`, nothing buffered).
fn put_idle(s: TcpStream) {
    let Ok(addr) = s.peer_addr() else { return };
    IDLE_BACKENDS.with(|p| {
        let mut map = p.borrow_mut();
        let n = IDLE_PUTS.with(|c| {
            let n = c.get().wrapping_add(1);
            c.set(n);
            n
        });
        if n % POOL_SWEEP_EVERY == 0 {
            for v in map.values_mut() {
                v.retain(|(_, since)| since.elapsed() < POOL_IDLE_TTL);
            }
            map.retain(|_, v| !v.is_empty());
        }
        let v = map.entry(addr).or_default();
        if v.len() < POOL_MAX_IDLE {
            v.push((s, Instant::now()));
        }
    });
}

/// Open one backend connection, honouring `backends.*.fast_open`.
///
/// TFO here is `TCP_FASTOPEN_CONNECT`: `connect` returns immediately and the
/// first write rides along in the SYN. monoio sets it best-effort, so a kernel
/// that refuses simply falls back to a normal handshake.
async fn connect_backend(addr: SocketAddr, fast_open: bool) -> io::Result<TcpStream> {
    if fast_open {
        let opts = monoio::net::TcpConnectOpts::new().tcp_fast_open(true);
        TcpStream::connect_addr_with_config(addr, &opts).await
    } else {
        TcpStream::connect_addr(addr).await
    }
}

/// `timeouts.keepalive` as a duration; `None` when disabled (0).
fn keepalive_of(cfg: &Config) -> Option<Duration> {
    match cfg.timeouts.keepalive {
        0 => None,
        s => Some(Duration::from_secs(s)),
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
    fn acquire(
        shards: &'a [Mutex<HashMap<IpAddr, u32>>; IP_SHARDS],
        ip: IpAddr,
        limit: usize,
    ) -> Option<Self> {
        let map = &shards[ip_shard(ip)];
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
    keepalive: Option<Duration>,
}

impl crate::terminate::BackendDial for Dialer {
    fn release(&self, s: TcpStream) {
        put_idle(s);
    }

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
            let addr = pool.addr(cand);
            // A parked connection skips the handshake entirely — the whole point
            // of the pool. It was tuned when it was first opened.
            if let Some(s) = take_idle(addr) {
                return Ok(s);
            }
            let dial = connect_backend(addr, pool.fast_open);
            match monoio::time::timeout(self.connect_timeout, dial).await {
                Ok(Ok(s)) => {
                    tune_stream(&s, self.keepalive);
                    return Ok(s);
                }
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
    let keepalive = keepalive_of(&st.cfg);
    // Idle read deadline for the post-handshake phases (terminate / terminate_tcp
    // / redirect). Unlike passthrough — which splice reaps via TCP keepalive —
    // these paths parse in user space and would otherwise let a client that
    // finished the TLS handshake then dribbles bytes pin an fd, a task, and a
    // backend connection indefinitely (slowloris). Every user-space read is
    // bounded by this.
    let idle = Duration::from_secs(st.cfg.timeouts.idle);
    tune_stream(&client, keepalive);

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
    // `scratch` is read into and reused across iterations, the same owned-buffer
    // cycle splice/tunnel use — no per-read allocation even when a DPI-bypass
    // client dribbles the hello a few bytes at a time and spins this loop.
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut scratch = vec![0u8; 4096];
    let sni = loop {
        let (res, b) = match monoio::time::timeout(hs_timeout, client.read(scratch)).await {
            Ok(v) => v,
            Err(_) => return Ok(()), // handshake timeout (slowloris) — drop
        };
        scratch = b;
        let n = res?;
        if n == 0 {
            return Ok(()); // client closed before we could route
        }
        buf.extend_from_slice(&scratch[..n]);
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
        let bm = pool.metrics.clone();
        metrics::GLOBAL.conns_total.fetch_add(1, Ordering::Relaxed);
        bm.conns_total.fetch_add(1, Ordering::Relaxed);
        let rules = st
            .cfg
            .backends
            .get(backend_name)
            .map(|b| b.http_rules.as_slice())
            .unwrap_or(&[]);
        let res = crate::redirect::handle(&buf, &mut client, rules, idle).await;
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

    let bm = pool.metrics.clone();
    let connect_timeout = Duration::from_secs(st.cfg.timeouts.connect);

    // The terminate TLS context (if any). `terminate` mode defers its backend
    // connect entirely: the HTTP request loop (and the h2 gateway) obtain a
    // backend connection per request through the pool, so an eagerly-opened one
    // would just be discarded. `terminate_tcp` (a raw tunnel) still pre-connects.
    let term_ctx = match pool.mode {
        Mode::Terminate | Mode::TerminateTcp => shared.terminate.get(backend_name),
        _ => None,
    };
    let defer_connect = pool.mode == Mode::Terminate;

    // Connect with retry across the pool unless this backend defers its connect.
    // On failure try the next server (healthy first); a live failure also marks
    // the server down when health checks are on, so the checker owns recovery.
    // `conn_guard` holds the least-conn counter for the chosen server; it stays
    // `None` on the deferred path (h2 least-conn is per-stream, tracked there).
    let mut conn_guard: Option<ConnGuard> = None;
    let backend_tcp: Option<TcpStream> = if defer_connect {
        None
    } else {
        let mut tried: Vec<usize> = Vec::new();
        loop {
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
            let dial = connect_backend(pool.addr(cand), pool.fast_open);
            match monoio::time::timeout(connect_timeout, dial).await {
                Ok(Ok(s)) => {
                    tune_stream(&s, keepalive);
                    conn_guard = Some(ConnGuard::new(pool, cand));
                    break Some(s);
                }
                _ => {
                    if pool.health_check() {
                        pool.set_healthy(cand, false);
                    }
                }
            }
        }
    };
    let _guard = conn_guard;
    let _active = ActiveGuard::new(bm.clone());

    if pool.mode == Mode::Terminate {
        // `backend_tcp` is always None here (terminate defers its connect); the
        // handler obtains backend connections per request through the dialer/pool.
        let res = match term_ctx {
            Some(ctx) => {
                // Dialer for per-request / per-stream backend connects — built
                // only on the terminate path (passthrough never needs it). Owns
                // the shared state so each spawned h2 stream task can clone it.
                let dialer = Dialer {
                    shared: shared.clone(),
                    backend: backend_name.to_string(),
                    connect_timeout,
                    keepalive,
                };
                crate::terminate::handle(buf, client, peer, &sni, ctx, dialer, idle).await
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
        // PROXY protocol is prepended to the backend stream. This path never
        // defers, so `backend_tcp` is the pre-connected stream.
        let backend_tcp = match backend_tcp {
            Some(b) => b,
            None => return Ok(()),
        };
        let proxy_header = match pool.proxy_protocol {
            ProxyProtocol::None => None,
            ProxyProtocol::V1 => Some(proxy_protocol::v1(peer, local)),
            ProxyProtocol::V2 => Some(proxy_protocol::v2(peer, local, false)),
        };
        let res = match term_ctx {
            Some(ctx) => {
                crate::terminate::handle_raw(buf, client, backend_tcp, ctx, proxy_header, idle).await
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

    // Passthrough never defers its connect, so `backend_tcp` is present.
    let mut upstream = match backend_tcp {
        Some(b) => b,
        None => return Ok(()),
    };
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

/// Rebuild reloadable state from the config file. Invalid configs are
/// rejected; the running config keeps serving. Changes that can't be
/// hot-swapped (listener bind/proto, terminate TLS, `default_tls`,
/// admin/metrics/log) trigger a fast restart — same semantics as the admin
/// API's `apply_config`, so SIGHUP never silently ignores part of an edit.
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
    match shared.apply_config(cfg) {
        Applied::HotSwapped => tracing::info!("configuration reloaded"),
        Applied::RestartRequired => {
            // Accept sockets and terminate TLS contexts are built once at
            // startup and can't change inside a running monoio runtime, so a
            // fresh bind is needed. Re-exec: fast (no drain), keeps the same
            // PID for systemd. Config is already validated, so the new image
            // will start cleanly.
            tracing::warn!(
                "reload: non-hot-swappable change (listeners/TLS/api/log) — \
                 fast-restarting to apply (active connections will drop)"
            );
            fast_restart();
        }
    }
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
    let exe = exe_path();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let err = std::process::Command::new(exe).args(args).exec();
    tracing::error!(error = %err, "fast restart (re-exec) failed; exiting");
    std::process::exit(1);
}

#[cfg(not(unix))]
pub fn fast_restart() -> ! {
    std::process::exit(1);
}

/// Path to exec on a fast restart.
///
/// `current_exe()` is `readlink /proc/self/exe`. After a self-update renamed a
/// new binary over ours, the old inode is unlinked and that link resolves to
/// `"<path> (deleted)"` — returned as `Ok`, so exec would fail with ENOENT and
/// kill the process instead of restarting it. Strip the marker to reach the
/// binary now holding the path. Only when the reported path is really gone, so
/// a file genuinely named `... (deleted)` still execs itself.
#[cfg(unix)]
fn exe_path() -> PathBuf {
    let p = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
    // Only when the reported path is really gone, so a file genuinely named
    // "... (deleted)" still execs itself.
    if p.exists() {
        return p;
    }
    strip_deleted(&p)
}

/// Drop procfs's `" (deleted)"` marker from an unlinked binary's path.
#[cfg(unix)]
fn strip_deleted(p: &std::path::Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    match p.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
        Some(real) => PathBuf::from(std::ffi::OsStr::from_bytes(real)),
        None => p.to_path_buf(),
    }
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
    /// The backend socket, `connect`ed to the chosen server so the kernel drops
    /// datagrams from any other source. `None` until the flow is routed.
    upstream: Option<Rc<UdpSocket>>,
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
    let mut last_sweep = Instant::now();
    // One buffer for the worker's lifetime, cycled through recv/send the same
    // way the backend->client pump below does. io_uring needs owned buffers, so
    // it is moved into each call and handed back — not allocated per datagram.
    let mut buf = vec![0u8; UDP_DGRAM_MAX];

    loop {
        let (res, b) = sock.recv_from(buf).await;
        buf = b;
        let (n, peer) = match res {
            Ok(v) => v,
            Err(_) => continue,
        };
        metrics::GLOBAL.udp_datagrams.fetch_add(1, Ordering::Relaxed);

        // Reap idle flows on a timer, not per packet, and only touch the shared
        // state here (the established-flow hot path below needs none of it).
        if last_sweep.elapsed() >= UDP_SWEEP_INTERVAL {
            let idle = Duration::from_secs(shared.state.load().cfg.timeouts.idle);
            flows.retain(|_, f| f.last.elapsed() < idle);
            last_sweep = Instant::now();
        }

        if let Some(flow) = flows.get_mut(&peer) {
            flow.last = Instant::now();
            if flow.routed {
                // The hot path for an established flow: forward the read buffer
                // itself on the connected socket and take it back — no copy, no
                // allocation, and no shared-state load.
                if let Some(up) = &flow.upstream {
                    let (_, slice) = up.send(buf.slice(..n)).await;
                    buf = slice.into_inner();
                }
                continue;
            }
            // Still collecting the ClientHello: these copies are bounded by the
            // handshake and are not the steady state.
            flow.pending.push(buf[..n].to_vec());
            if let Some(sni) = advance_quic(flow, &buf[..n]) {
                route_udp(&mut flows, peer, sni, local, listener_idx, &shared, &sock).await;
            }
            continue;
        }

        // New flow — the one place that needs the shared state (ACL + capacity).
        let st = shared.state.load_full();
        if let Some(acl) = st.acls.get(listener_idx).and_then(|a| a.as_ref()) {
            if !acl.ip_allowed(peer.ip()) {
                continue; // IP not permitted on this listener
            }
        }
        if flows.len() >= MAX_UDP_FLOWS {
            continue; // shed load rather than grow unbounded
        }
        let mut flow = Flow {
            upstream: None, // set on routing
            routed: false,
            reasm: quic::CryptoReasm::new(),
            pending: vec![buf[..n].to_vec()],
            last: Instant::now(),
        };
        let decided = advance_quic(&mut flow, &buf[..n]);
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
    let bm = pool.metrics.clone();
    let idx = pool.pick();
    let addr = pool.addr(idx);

    // Connected backend socket: `send`/`recv` (no per-datagram destination, so
    // no FIB lookup on the send path) and — the security point — the kernel
    // delivers only datagrams from `addr`, so nobody who guesses the ephemeral
    // source port can inject forged "backend" replies toward the client.
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
            let _ = up.send(proxy_protocol::v1(peer, local)).await.0;
        }
        ProxyProtocol::V2 => {
            let _ = up.send(proxy_protocol::v2(peer, local, true)).await.0;
        }
    }

    let idle = Duration::from_secs(st.cfg.timeouts.idle);
    let Some(flow) = flows.get_mut(&peer) else { return };
    flow.upstream = Some(up.clone());
    flow.routed = true;
    let pending = std::mem::take(&mut flow.pending);
    for d in pending {
        let _ = up.send(d).await.0;
    }

    // Pump backend -> client for this flow.
    let sock = sock.clone();
    monoio::spawn(async move {
        let mut buf = vec![0u8; UDP_DGRAM_MAX];
        loop {
            let (res, b) = match monoio::time::timeout(idle, up.recv(buf)).await {
                Ok(v) => v,
                Err(_) => break,
            };
            buf = b;
            let n = match res {
                Ok(0) => break,
                Ok(n) => n,
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

/// A UDP socket `connect`ed to a backend. Connecting (rather than leaving it
/// open) does two things: `send`/`recv` skip the per-datagram route lookup, and
/// the kernel drops any datagram whose source isn't `backend` — so a third party
/// can't inject forged replies into the flow. We use `send`, never `send_to`, so
/// there's no `EISCONN`.
fn connect_udp(backend: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if backend.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let std_sock = std::net::UdpSocket::bind(bind)?;
    std_sock.connect(backend)?;
    UdpSocket::from_std(std_sock)
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------

fn reuseport_tcp(
    addr: SocketAddr,
    l: &crate::config::Listener,
    defer_accept_secs: u32,
) -> io::Result<std::net::TcpListener> {
    let sock = new_reuseport_socket(addr, Type::STREAM, SockProto::TCP)?;
    if l.fast_open {
        set_tcp_fastopen(&sock, l.fast_open_qlen())?;
    }
    // Every protocol we route is client-speaks-first (TLS ClientHello). Defer the
    // accept until the client's first data arrives, so accept hands us a socket
    // with the ClientHello already there — one fewer wakeup, and silent SYN-only
    // scanners never surface into user space. Best effort; a kernel that refuses
    // just falls back to normal accept.
    set_tcp_defer_accept(&sock, defer_accept_secs);
    sock.listen(l.backlog() as i32)?;
    Ok(sock.into())
}

/// `TCP_DEFER_ACCEPT`: don't complete an accept until data arrives (or `secs`
/// elapse). socket2 0.5 has no wrapper. Non-fatal — logged nowhere, since a
/// socket without it merely wakes a touch earlier.
fn set_tcp_defer_accept(sock: &Socket, secs: u32) {
    let v: libc::c_int = secs.max(1) as libc::c_int;
    // SAFETY: fd is owned by `sock` and outlives the call; `v` is a valid c_int
    // of the size the option expects.
    unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(sock),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            &v as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Enable TCP Fast Open on a listening socket. Must be set before `listen()`.
/// `qlen` bounds the pending-SYN queue (see `listeners[].fast_open_qlen`).
/// socket2 0.5 has no wrapper for this option.
/// Read back the TFO queue depth the kernel actually settled on.
///
/// Worth doing because this number is invisible from outside the process: it is
/// not carried by inet_diag, so `ss` cannot show it at any verbosity. And the
/// kernel silently clamps the requested value to `net.core.somaxconn`, so what
/// we asked for is not necessarily what we got. `getsockopt(TCP_FASTOPEN)`
/// reports the listener's `max_qlen`, which is the real thing.
fn get_tcp_fastopen(fd: std::os::fd::RawFd) -> io::Result<u32> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd is a live socket owned by the caller; val/len are valid
    // out-params of the size the option expects.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(val.max(0) as u32)
}

/// Report what a listener is really running with, once per address (core 0).
/// `backlog` is echoed as configured — `ss -tln` shows the effective value in
/// Send-Q — while the TFO queue is read back from the kernel, since nothing
/// outside this process can.
fn log_listener(addr: SocketAddr, l: &crate::config::Listener, fd: std::os::fd::RawFd) {
    if !l.fast_open {
        tracing::info!(%addr, backlog = l.backlog(), "tcp listener ready");
        return;
    }
    match get_tcp_fastopen(fd) {
        Ok(effective) => {
            tracing::info!(
                %addr,
                backlog = l.backlog(),
                fast_open_qlen = effective,
                "tcp listener ready (fast_open active)"
            );
            if effective != l.fast_open_qlen() {
                tracing::warn!(
                    %addr,
                    requested = l.fast_open_qlen(),
                    effective,
                    "fast_open_qlen was clamped by net.core.somaxconn"
                );
            }
        }
        Err(e) => tracing::warn!(%addr, error = %e, "cannot read back fast_open_qlen"),
    }
}

fn set_tcp_fastopen(sock: &Socket, qlen: u32) -> io::Result<()> {
    let qlen: libc::c_int = qlen as libc::c_int;
    // SAFETY: fd is owned by `sock` and outlives the call; qlen is a valid
    // c_int of the size we pass.
    let rc = unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(sock),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &qlen as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Also pins the reason the call exists: the kernel default really is Nagle
    /// on, so without `tune_stream` every forwarded byte pays for it.
    #[test]
    fn tune_stream_disables_nagle() {
        let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = l.local_addr().expect("local_addr");
            // connect completes on the kernel handshake; no accept needed.
            let c = TcpStream::connect(addr).await.expect("connect");
            assert!(!c.nodelay().expect("getsockopt"), "kernel default should be Nagle on");
            tune_stream(&c, Some(Duration::from_secs(30)));
            assert!(c.nodelay().expect("getsockopt"), "tune_stream must set TCP_NODELAY");
        });
    }

    #[test]
    fn strip_deleted_recovers_the_replaced_binary_path() {
        // What /proc/self/exe reports after a self-update renamed a new binary
        // over the running one — exec'ing it verbatim would fail with ENOENT.
        assert_eq!(
            strip_deleted(std::path::Path::new("/usr/local/lib/sni-router/sni-router (deleted)")),
            PathBuf::from("/usr/local/lib/sni-router/sni-router")
        );
        // Untouched binary: path passes through.
        assert_eq!(
            strip_deleted(std::path::Path::new("/usr/local/lib/sni-router/sni-router")),
            PathBuf::from("/usr/local/lib/sni-router/sni-router")
        );
    }
}
