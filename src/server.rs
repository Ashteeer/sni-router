//! The data path: per-core `monoio` workers accepting connections and
//! forwarding them to backends after SNI routing.
//!
//! Sharding is `SO_REUSEPORT` + thread-per-core: one runtime per core, each
//! with its own accept sockets bound to the same addresses. The kernel spreads
//! connections (and UDP 4-tuples) across the reuseport group, so no work
//! stealing and no cross-core locking on the hot path. Forwarding is a buffered
//! bidirectional copy.
//! ponytail: buffered copy, not `splice()` zero-copy yet — correct first; the
//! splice upgrade (io_uring `IORING_OP_SPLICE` via a pipe pair) is a drop-in
//! replacement for `copy_half` when throughput demands it.

use crate::backend::{ConnGuard, Pool};
use crate::config::{Config, Mode, Proto, ProxyProtocol};
use crate::protocol::{proxy_protocol, quic, tls};
use crate::router;

use monoio::buf::IoBuf;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::udp::UdpSocket;
use monoio::net::{TcpListener, TcpStream};

use socket2::{Domain, Protocol as SockProto, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

const UDP_DGRAM_MAX: usize = 2048;
const COPY_BUF: usize = 32 * 1024;
const MAX_UDP_FLOWS: usize = 100_000;
const UDP_SWEEP_EVERY: u32 = 512;

/// Immutable-ish state shared across all worker threads.
pub struct Shared {
    pub cfg: Config,
    pub pools: HashMap<String, Pool>,
    /// Compiled ACL per listener (indexed like `cfg.listeners`); `None` = no ACL.
    pub acls: Vec<Option<crate::acl::Acl>>,
    /// TLS contexts for terminate backends, keyed by backend name.
    pub terminate: HashMap<String, crate::terminate::TerminateCtx>,
}

/// Run the router until killed. Blocks the calling thread.
pub fn run(cfg: Config) -> io::Result<()> {
    let mut pools = HashMap::new();
    for (name, b) in &cfg.backends {
        if let Some(p) = Pool::from_backend(b) {
            pools.insert(name.clone(), p);
        }
    }
    let acls = cfg
        .listeners
        .iter()
        .map(|l| l.acl.as_ref().and_then(|a| crate::acl::Acl::compile(a).ok()))
        .collect();
    let terminate = crate::terminate::TerminateCtx::build_all(&cfg.backends);
    let shared = Arc::new(Shared { cfg, pools, acls, terminate });

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    eprintln!(
        "sni-router: starting {} listener(s) on {} core(s)",
        shared.cfg.listeners.len(),
        cores
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
            eprintln!("core {core}: failed to build runtime: {e}");
            return;
        }
    };

    rt.block_on(async move {
        let mut tasks = Vec::new();
        for (idx, l) in shared.cfg.listeners.iter().enumerate() {
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
                            Err(e) => eprintln!("core {core}: {addr} from_std: {e}"),
                        },
                        Err(e) => eprintln!("core {core}: bind tcp {addr}: {e}"),
                    },
                    Proto::Udp => match reuseport_udp(addr) {
                        Ok(std_s) => match UdpSocket::from_std(std_s) {
                            Ok(sock) => {
                                let sh = shared.clone();
                                tasks.push(monoio::spawn(udp_worker(sock, addr, idx, sh)));
                            }
                            Err(e) => eprintln!("core {core}: udp from_std {addr}: {e}"),
                        },
                        Err(e) => eprintln!("core {core}: bind udp {addr}: {e}"),
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
                let shared = shared.clone();
                monoio::spawn(async move {
                    let _ = handle_tcp(stream, peer, local, listener_idx, shared).await;
                });
            }
            Err(e) => {
                eprintln!("accept {local}: {e}");
                monoio::time::sleep(Duration::from_millis(20)).await;
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
    let cfg = &shared.cfg;
    let acl = shared.acls[listener_idx].as_ref();

    // IP ACL: reject before we spend any effort reading the handshake.
    if let Some(acl) = acl {
        if !acl.ip_allowed(peer.ip()) {
            return Ok(());
        }
    }

    let max = cfg.limits.max_client_hello;
    let hs_timeout = Duration::from_secs(cfg.timeouts.handshake);

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

    let routes = &cfg.listeners[listener_idx].routes;
    let backend_name = match router::pick(routes, &sni) {
        Some(b) => b,
        None => return Ok(()), // no matching route (and no catch-all) — drop
    };
    let pool = match shared.pools.get(backend_name) {
        Some(p) => p,
        None => return Ok(()),
    };
    let idx = pool.pick();
    let _guard = ConnGuard::new(pool, idx);
    let addr = pool.addr(idx);

    if pool.mode == Mode::Terminate {
        return match shared.terminate.get(backend_name) {
            Some(ctx) => crate::terminate::handle(buf, client, peer, &sni, addr, ctx).await,
            None => Ok(()), // TLS context failed to build at startup — drop
        };
    }

    let connect_timeout = Duration::from_secs(cfg.timeouts.connect);
    let mut upstream = match monoio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("connect {addr}: {e}");
            return Ok(());
        }
        Err(_) => {
            eprintln!("connect {addr}: timeout");
            return Ok(());
        }
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
    // Replay the buffered ClientHello verbatim, then splice the rest.
    upstream.write_all(buf).await.0?;

    let idle = Duration::from_secs(cfg.timeouts.idle);
    let (cr, cw) = client.into_split();
    let (ur, uw) = upstream.into_split();
    let up = monoio::spawn(copy_half(cr, uw, idle)); // client -> backend
    copy_half(ur, cw, idle).await; // backend -> client
    let _ = up.await;
    Ok(())
}

/// Copy one direction until EOF, error, or an idle-timeout with no data.
async fn copy_half<R, W>(mut r: R, mut w: W, idle: Duration)
where
    R: AsyncReadRent,
    W: AsyncWriteRent,
{
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let (res, b) = match monoio::time::timeout(idle, r.read(buf)).await {
            Ok(v) => v,
            Err(_) => break, // idle timeout
        };
        buf = b;
        let n = match res {
            Ok(0) => break, // EOF
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
async fn udp_worker(sock: UdpSocket, local: SocketAddr, listener_idx: usize, shared: Arc<Shared>) {
    let sock = Rc::new(sock);
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut ticks: u32 = 0;
    let idle = Duration::from_secs(shared.cfg.timeouts.idle);

    loop {
        let buf = vec![0u8; UDP_DGRAM_MAX];
        let (res, buf) = sock.recv_from(buf).await;
        let (n, peer) = match res {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dgram = &buf[..n];

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
        if let Some(acl) = shared.acls[listener_idx].as_ref() {
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
    // SNI ACL for the QUIC listener.
    if let Some(acl) = shared.acls[listener_idx].as_ref() {
        if !acl.sni_allowed(&sni) {
            flows.remove(&peer);
            return;
        }
    }

    let routes = &shared.cfg.listeners[listener_idx].routes;
    let decision = router::pick(routes, &sni)
        .and_then(|name| shared.pools.get(name))
        .filter(|p| p.mode != Mode::Terminate); // terminate not valid for udp

    let Some(pool) = decision else {
        flows.remove(&peer);
        return;
    };
    let idx = pool.pick();
    let addr = pool.addr(idx);

    let up = match connect_udp(addr) {
        Ok(u) => Rc::new(u),
        Err(e) => {
            eprintln!("udp connect {addr}: {e}");
            flows.remove(&peer);
            return;
        }
    };

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
    let idle = Duration::from_secs(shared.cfg.timeouts.idle);
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
