//! Backend pools: address parsing plus round-robin / least-conn selection.
//!
//! Selection counters are shared across all per-core workers (plain atomics in
//! an `Arc`), so balancing stays accurate even though each core runs its own
//! thread-per-core runtime. ponytail: shared atomics, not per-core approximate
//! counters — a contended `fetch_add` is far cheaper than routing to a
//! lopsided backend.

use crate::config::{Backend, Balance, Mode, ProxyProtocol};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Pool {
    pub servers: Vec<SocketAddr>,
    pub mode: Mode,
    pub proxy_protocol: ProxyProtocol,
    pub balance: Balance,
    rr: AtomicUsize,
    conns: Vec<AtomicUsize>,
}

impl Pool {
    /// Build a pool from a validated backend. Returns `None` only if no server
    /// address parses (the validator rejects that before we get here).
    pub fn from_backend(b: &Backend) -> Option<Pool> {
        let servers: Vec<SocketAddr> =
            b.servers.iter().filter_map(|s| s.parse().ok()).collect();
        if servers.is_empty() {
            return None;
        }
        let conns = servers.iter().map(|_| AtomicUsize::new(0)).collect();
        Some(Pool {
            servers,
            mode: b.mode,
            proxy_protocol: b.proxy_protocol,
            balance: b.balance,
            rr: AtomicUsize::new(0),
            conns,
        })
    }

    /// Pick a server index according to the balancing policy.
    pub fn pick(&self) -> usize {
        match self.balance {
            Balance::RoundRobin => self.rr.fetch_add(1, Ordering::Relaxed) % self.servers.len(),
            Balance::LeastConn => {
                let mut best = 0;
                let mut best_n = usize::MAX;
                for (i, c) in self.conns.iter().enumerate() {
                    let n = c.load(Ordering::Relaxed);
                    if n < best_n {
                        best_n = n;
                        best = i;
                    }
                }
                best
            }
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
            health_check: false,
            tls: None,
            headers: Default::default(),
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
    fn guard_decrements_on_drop() {
        let p = Pool::from_backend(&backend(&["10.0.0.1:1"], Balance::LeastConn)).unwrap();
        {
            let _g = ConnGuard::new(&p, 0);
            assert_eq!(p.conns[0].load(Ordering::Relaxed), 1);
        }
        assert_eq!(p.conns[0].load(Ordering::Relaxed), 0);
    }
}
