# sni-router

High-performance SNI-based L4 router / proxy for Linux.

Routes TCP, UDP and QUIC connections by TLS SNI (Server Name Indication)
**without terminating TLS** — the handshake passes through untouched and
backends keep their own certificates. An optional TLS-termination mode is
planned.

Same class of tool as `sniproxy` / `sslh` / `nginx stream + ssl_preread`, but:

- **built for raw performance** — io_uring (`monoio`, thread-per-core),
  zero-copy `splice()` forwarding, `SO_REUSEPORT` sharding with CPU pinning;
- **TCP _and_ UDP/QUIC** out of the box, not TCP only;
- **a config file a human can read** — flat YAML, sane defaults, first-match
  routing. Closer to HAProxy than to Envoy, and simpler than both.

## Status

Early development — **not production-ready yet**.

| Milestone | State |
|---|---|
| Config parsing + static validation (`sni-router -t`, like `nginx -t`) | done |
| TCP passthrough with SNI extraction | next |
| PROXY protocol v1/v2 (real client IP for backends) | planned |
| UDP/QUIC passthrough (SNI from the QUIC Initial packet) | planned |
| Backend pools: round-robin / least-conn, health checks | planned |
| Hot reload on SIGHUP (validate first, keep old config on failure) | planned |
| Rate limiting, Prometheus metrics, access logs | planned |
| TLS termination mode (`mode: terminate`) | post-MVP |

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
    mode: passthrough             # passthrough | terminate
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
