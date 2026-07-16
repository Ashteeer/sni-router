//! Backend pools: address parsing plus round-robin / least-conn selection.
//!
//! Selection counters are shared across all per-core workers (plain atomics in
//! an `Arc`), so balancing stays accurate even though each core runs its own
//! thread-per-core runtime. ponytail: shared atomics, not per-core approximate
//! counters — a contended `fetch_add` is far cheaper than routing to a
//! lopsided backend.

use crate::config::{Backend, Balance, Mode, ProxyProtocol};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Pool {
    pub servers: Vec<SocketAddr>,
    pub mode: Mode,
    pub proxy_protocol: ProxyProtocol,
    pub balance: Balance,
    /// Connect to servers with TCP Fast Open (`backends.*.fast_open`).
    pub fast_open: bool,
    health_check: bool,
    rr: AtomicUsize,
    conns: Vec<AtomicUsize>,
    /// Per-server up/down flag maintained by the health checker and by connect
    /// failures (only consulted when `health_check` is on).
    healthy: Vec<AtomicBool>,
}

impl Pool {
    /// Build a pool from a validated backend. Returns `None` only if no server
    /// address parses (the validator rejects that before we get here).
    pub fn from_backend(b: &Backend) -> Option<Pool> {
        let servers: Vec<SocketAddr> =
            b.servers.iter().filter_map(|s| s.parse().ok()).collect();
        // redirect_https answers directly and never picks a server, so an empty
        // pool is valid for it; every other mode needs at least one server.
        if servers.is_empty() && b.mode != Mode::RedirectHttps {
            return None;
        }
        let conns = servers.iter().map(|_| AtomicUsize::new(0)).collect();
        let healthy = servers.iter().map(|_| AtomicBool::new(true)).collect();
        Some(Pool {
            servers,
            mode: b.mode,
            proxy_protocol: b.proxy_protocol,
            balance: b.balance,
            fast_open: b.fast_open,
            health_check: b.health_check,
            rr: AtomicUsize::new(0),
            conns,
            healthy,
        })
    }

    pub fn health_check(&self) -> bool {
        self.health_check
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    pub fn set_healthy(&self, idx: usize, up: bool) {
        self.healthy[idx].store(up, Ordering::Relaxed);
    }

    /// Pick a server for a UDP flow (no retry, so no health filtering).
    pub fn pick(&self) -> usize {
        self.balance_over(&(0..self.servers.len()).collect::<Vec<_>>())
    }

    /// Pick the next server to try, excluding those already `tried`. Healthy
    /// servers are preferred; if all healthy ones are exhausted it falls back to
    /// unhealthy ones (fail-open — better to try than to blackhole). Returns
    /// `None` once every server has been tried.
    pub fn pick_candidate(&self, tried: &[usize]) -> Option<usize> {
        let eligible = |only_healthy: bool| -> Vec<usize> {
            (0..self.servers.len())
                .filter(|i| {
                    !tried.contains(i) && (!only_healthy || self.healthy[*i].load(Ordering::Relaxed))
                })
                .collect()
        };
        let set = if self.health_check {
            let healthy = eligible(true);
            if healthy.is_empty() { eligible(false) } else { healthy }
        } else {
            eligible(false)
        };
        if set.is_empty() {
            None
        } else {
            Some(self.balance_over(&set))
        }
    }

    /// Apply the balancing policy over a set of candidate indices.
    fn balance_over(&self, set: &[usize]) -> usize {
        match self.balance {
            Balance::RoundRobin => set[self.rr.fetch_add(1, Ordering::Relaxed) % set.len()],
            Balance::LeastConn => *set
                .iter()
                .min_by_key(|i| self.conns[**i].load(Ordering::Relaxed))
                .expect("non-empty set"),
        }
    }

    pub fn addr(&self, idx: usize) -> SocketAddr {
        self.servers[idx]
    }

    pub fn inc(&self, idx: usize) {
        self.conns[idx].fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self, idx: usize) {
        self.conns[idx].fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard that decrements the least-conn counter when a connection ends.
pub struct ConnGuard<'a> {
    pool: &'a Pool,
    idx: usize,
}

impl<'a> ConnGuard<'a> {
    pub fn new(pool: &'a Pool, idx: usize) -> Self {
        pool.inc(idx);
        ConnGuard { pool, idx }
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.pool.dec(self.idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Backend;

    fn backend(servers: &[&str], balance: Balance) -> Backend {
        Backend {
            mode: Mode::Passthrough,
            proxy_protocol: ProxyProtocol::None,
            balance,
            fast_open: false,
            health_check: false,
            tls: None,
            backend_tls: None,
            headers: Default::default(),
            http2: false,
            http_rules: Vec::new(),
            servers: servers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn round_robin_cycles() {
        let p = Pool::from_backend(&backend(&["10.0.0.1:1", "10.0.0.2:2"], Balance::RoundRobin))
            .unwrap();
        let seq: Vec<usize> = (0..4).map(|_| p.pick()).collect();
        assert_eq!(seq, vec![0, 1, 0, 1]);
    }

    #[test]
    fn least_conn_prefers_idle_server() {
        let p = Pool::from_backend(&backend(&["10.0.0.1:1", "10.0.0.2:2"], Balance::LeastConn))
            .unwrap();
        let _g = ConnGuard::new(&p, 0); // server 0 now has 1 connection
        assert_eq!(p.pick(), 1); // least loaded
    }

    #[test]
    fn candidate_excludes_tried_and_prefers_healthy() {
        let mut b = backend(&["10.0.0.1:1", "10.0.0.2:2", "10.0.0.3:3"], Balance::RoundRobin);
        b.health_check = true;
        let p = Pool::from_backend(&b).unwrap();
        p.set_healthy(0, false);
        // server 0 is down, so it must not be the first candidate.
        assert_ne!(p.pick_candidate(&[]).unwrap(), 0);
        // once the healthy ones are tried, fall back to the unhealthy one.
        assert_eq!(p.pick_candidate(&[1, 2]).unwrap(), 0);
        // everything tried -> give up.
        assert_eq!(p.pick_candidate(&[0, 1, 2]), None);
    }

    #[test]
    fn guard_decrements_on_drop() {
        let p = Pool::from_backend(&backend(&["10.0.0.1:1"], Balance::LeastConn)).unwrap();
        {
            let _g = ConnGuard::new(&p, 0);
            assert_eq!(p.conns[0].load(Ordering::Relaxed), 1);
        }
        assert_eq!(p.conns[0].load(Ordering::Relaxed), 0);
    }
}
