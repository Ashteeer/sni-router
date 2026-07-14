# sni-router

High-performance SNI-aware edge router for Linux.

sni-router accepts TCP, UDP and QUIC connections and decides what to do with
each one from the TLS SNI (Server Name Indication) — per backend, and without
forcing a single behaviour on the whole port:

- **Passthrough** — route by SNI and forward the raw stream, TLS untouched, so
  backends keep their own certificates. Zero-copy on the fast path.
- **Terminate** — terminate TLS at the router and act as a reverse proxy:
  HTTP/1.1 and HTTP/2, header injection (`X-Real-IP` / `X-Forwarded-*`),
  WebSocket upgrades, optional re-encrypt/mTLS to the backend, and per-path
  rules (forward, synthetic responses, redirects).
- **Raw-TCP terminate** — strip TLS and hand the backend a plain TCP stream,
  for DoT (`:853`) and other non-HTTP protocols behind TLS.
- **Redirect** — answer plaintext HTTP on `:80` with a `301` to `https://`.

One listener can mix all of these across different SNI names. The same tool
therefore covers what usually takes `sniproxy`/`sslh` for passthrough *and* a
separate HTTP reverse proxy for termination.

Design priorities, in order:

- **Raw performance** — io_uring (`monoio`, thread-per-core), zero-copy
  `splice()` forwarding, `SO_REUSEPORT` sharding with CPU pinning.
- **TCP _and_ UDP/QUIC** out of the box, not TCP only.
- **A config a human can read** — flat YAML, sane defaults, first-match
  routing. Closer to HAProxy than to Envoy, and simpler than both. See
  [`config.md`](config.md) for the complete reference.

## Status

**v1.0.0** — feature-complete for the capabilities listed below, with unit
tests and live integration tests on real traffic. It handles untrusted input
(anonymous TLS/QUIC ClientHellos), so roll it out deliberately and validate
your config with `sni-router -t` first.

| Milestone | State |
|---|---|
| Config parsing + static validation (`sni-router -t`, like `nginx -t`) | done |
| TCP passthrough with SNI extraction (robust to fragmented ClientHello) | done |
| PROXY protocol v1/v2 (real client IP for backends) | done |
| UDP/QUIC passthrough (SNI from the QUIC Initial packet) | done |
| Backend pools: round-robin / least-conn | done |
| TLS termination mode + `X-Forwarded-*` header injection | done |
| Re-encrypt to TLS backends (`backend_tls`) + mTLS | done |
| Access control (allow/deny by client IP CIDR and SNI) | done |
| QUIC v2 (RFC 9369) Initial decryption | done |
| Management + metrics API — one bind, one token (`/status`, `/config`, `/healthz`, `/metrics`, `/version`, `PUT`/`POST` writes) | done |
| Self-update — `sni-router -u` / `POST /update` (fetch latest release, replace binary, restart) | done |
| Zero-downtime cert reload (certbot/lego renewals) | done |
| Backend health checks (TCP probe) + connect retry across the pool | done |
| Zero-copy `splice()` TCP forwarding | done |
| WebSocket / HTTP Upgrade tunneling in terminate mode | done |
| Hot reload on SIGHUP (validate first, keep old config on failure) | done |
| Structured access logs + `tracing` (text/json) | done |
| Rate limiting (`max_conns_per_ip`) | done |
| Graceful drain on SIGTERM | done |
| `:80`→`:443` redirect (`mode: redirect_https`) | done |
| Raw-TCP terminate for DoT etc. (`mode: terminate_tcp`) | done |
| Per-path rules + synthetic `direct_response` in terminate | done |
| HTTP/2 termination (`h2` ALPN → HTTP/1.1 backend gateway) | done |

**Resilience to DPI-bypass clients (Zapret / GoodbyeDPI / byedpi):** the SNI
parser never assumes the ClientHello arrives in one piece — it reassembles
across TCP segments and TLS records, and fake packets (bad checksum / TTL) are
dropped by the kernel before they reach it. On QUIC, a fake Initial simply
fails AEAD authentication and is ignored while the real one is awaited.

## Quick start

> Requires a published release; until the first one exists, build from source
> (see below).

```bash
wget https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
sudo bash install.sh
```

The installer detects your architecture (x86_64 / aarch64), downloads the
latest release binary to `/usr/local/bin/sni-router`, puts a default config in
`/etc/sni-router/sni-router.yaml` and registers a systemd unit — **without
starting it**, so nothing touches ports until you say so:

```bash
sudo nano /etc/sni-router/sni-router.yaml   # pick bind addresses that are free
sni-router -t                               # validate (never binds anything)
sudo systemctl enable --now sni-router
```

Full server guide: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Configuration

```yaml
listeners:
  - name: main_tls
    bind: ["0.0.0.0:443", "[::]:443"]
    proto: tcp                    # tcp | udp (udp = QUIC)
    routes:                       # first match wins
      - sni: "example.com"
        backend: web_main
      - sni: "*.example.com"      # any subdomain, not example.com itself
        backend: web_main
      - sni: "*"                  # catch-all
        backend: default_pool

backends:
  web_main:
    mode: passthrough             # passthrough | terminate | terminate_tcp | redirect_https
    proxy_protocol: v2            # none | v1 | v2 — pass the real client IP
    balance: round_robin          # round_robin | least_conn
    servers:
      - "10.0.0.1:443"
      - "10.0.0.2:443"

  default_pool:                   # minimal backend: everything defaulted
    servers:
      - "10.0.0.9:443"

timeouts:                         # seconds
  handshake: 5
  connect: 10
  idle: 300
```

Annotated example: [config/sni-router.example.yaml](config/sni-router.example.yaml).

### Validation

Static check of the whole file — collects **all** errors at once, with exact
config paths and `cargo`-style "did you mean" suggestions:

```bash
sni-router -t                        # default path /etc/sni-router/sni-router.yaml
sni-router -t /path/to/config.yaml   # explicit path
sni-router -t --check-backends       # additionally TCP-probe every backend server
```

Exit code is `0` when the config is valid (warnings allowed), non-zero
otherwise — safe to use as a gate in deploy scripts:

```bash
sni-router -t && sudo systemctl reload sni-router
```

The config path can also be set via the `SNI_ROUTER_CONFIG` environment
variable.

## Build from source

Linux only (io_uring / `splice`). Requires stable Rust
([rustup.rs](https://rustup.rs)).

```bash
git clone https://github.com/Ashteeer/sni-router
cd sni-router
cargo build --release
./target/release/sni-router --help
```

## License

Apache-2.0
