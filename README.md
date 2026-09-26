# sni-router

Route TLS connections by hostname without taking over their certificates.

sni-router is a Linux proxy for TCP, UDP and QUIC. It reads the server name
from a TLS ClientHello, selects a backend from a YAML routing table, and
forwards the connection. In passthrough mode, TLS stays between the client
and the backend. Services with different hostnames can share one address
and port.

For services that need TLS to end at the router, a backend can instead use
HTTP termination or raw TCP termination. This is useful when an HTTPS app,
a TLS tunnel and a DNS-over-TLS resolver sit behind the same machine but
need different handling.

[Installation](docs/installation.md) · [Configuration](docs/configuration.md) ·
[Examples](config/examples/) · [Releases](https://github.com/Ashteeer/sni-router/releases)

## How it fits

```text
                         sni-router                   backends
                    ┌──────────────────┐
 app.example.com ────┤                  ├── passthrough ── HTTPS server
 api.example.com ────┤ :443 TCP, by SNI  ├── terminate ──── HTTP application
 dns.example.com ────┤                  ├── terminate_tcp ─ DNS server
                    └──────────────────┘
 app.example.com ───── :443 UDP, QUIC SNI ── passthrough ── HTTP/3 server
```

The listener defines where traffic arrives. The backend defines what happens
to it. TCP routes on one listener can use different backend modes; UDP routes
use passthrough only.

| Mode | Client side | Backend side | Certificates on the router |
| --- | --- | --- | --- |
| `passthrough` | TCP, or UDP including QUIC v1/v2 | Original stream or datagrams | No |
| `terminate` | HTTPS: HTTP/1.1, optional HTTP/2 | HTTP/1.1, optionally TLS for HTTP/1.1 clients | Yes |
| `terminate_tcp` | TLS carrying any TCP protocol | Plain TCP | Yes |
| `redirect_https` | Plain HTTP | Local redirect or response; no upstream | No |

TCP passthrough uses `splice(2)` with a buffered fallback. Workers run on
monoio, one per available CPU, with `SO_REUSEPORT` listeners and CPU affinity.
Other supported features include backend pools, TCP health probes, PROXY
protocol, IP/SNI access lists, WebSocket upgrades, certificate reloads and a
management API with Prometheus metrics.

## A small routing config

This example sends two hostnames to separate TLS servers. The backends own
their certificates; the router needs none. Replace the hostnames and upstream
addresses with yours, and point both DNS names at the router.

```yaml
listeners:
  - name: tls
    bind: ["0.0.0.0:443"]
    routes:
      - sni: "app.example.com"
        backend: app
      - sni: "api.example.com"
        backend: api

backends:
  app:
    servers: ["127.0.0.1:8443"]
  api:
    servers: ["127.0.0.1:9443"]
```

`proto: tcp` and `mode: passthrough` are the defaults. Routes are checked in
order; the first match wins. A connection without a matching name is closed.
Add `sni: "*"` as the last route only if you want a fallback, including for
clients without SNI. `*.example.com` matches subdomains at any depth, but
does not match `example.com` itself.

Validate a saved file without binding ports:

```bash
sni-router -t ./sni-router.yaml
```

The [routing guide](docs/routing.md) explains fallback behavior, plaintext
traffic, UDP flows and how to carry the client's address to a backend.

## Install and run

Release binaries are provided for Linux x86_64. See the
[installation guide](docs/installation.md) for runtime requirements,
checksum verification and building for other architectures.

```bash
curl -fsSLo install.sh https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
less install.sh
sudo bash install.sh
```

**A fresh installation starts the service immediately.** It creates an
API-only config, listens on `0.0.0.0` at a generated port, and prints a bearer
token. Without `--cert` and `--key`, this API uses HTTP. Restrict access to
that port before installation, or supply a certificate as described in the
[installation guide](docs/installation.md#install-with-systemd).

The config lives at `/etc/sni-router/sni-router.yaml`. Add your `listeners`
and `backends` to that file, keeping the generated `api` section if you use
remote management. Then validate and apply it:

```bash
sudo sni-router -t /etc/sni-router/sni-router.yaml && sudo systemctl reload sni-router
journalctl -u sni-router -n 30 --no-pager
```

Invalid configurations are rejected. Route changes can be applied in place;
changes such as listener addresses or TLS settings restart the process and
disconnect clients. The [reload table](docs/operations.md) describes the
difference. To run without systemd, use `sni-router -c ./sni-router.yaml`.

## Documentation

| Read this | To do this |
| --- | --- |
| [Installation](docs/installation.md) | Install a release, verify it, or build from source |
| [Configuration reference](docs/configuration.md) | Look up every YAML field, default and restriction |
| [Routing](docs/routing.md) | Choose modes, order routes and forward client addresses |
| [Example configurations](config/examples/) | Start with passthrough, HTTPS, DoT, DNS or API-only setups |
| [Operations](docs/operations.md) | Reload, update, renew certificates and diagnose failures |
| [Management API](docs/api.md) | Read status, replace configs and integrate monitoring |
| [Architecture](docs/architecture.md) | Understand workers, forwarding, reloads and current limits |
| [Contributing](CONTRIBUTING.md) | Build, test and submit changes |

## Scope and limitations

This is an actively developed proxy with a deliberately small configuration
surface. It does not include a web UI or an ACME client; use an external
certificate manager such as certbot or lego.

QUIC is forwarded, not terminated. Connection migration is unsupported, and
encrypted ClientHello names cannot be used for routing. Ordinary UDP has no
SNI and needs a catch-all route. Backend addresses must be literal IP addresses
with ports; DNS names are not resolved.

HTTP/2 termination is a gateway to plaintext HTTP/1.1 upstreams, without
server push or trailers. The HTTP and UDP paths also have outstanding
correctness and resource-limit issues described under
[known limitations](docs/architecture.md#known-limitations). Check these
before exposing a deployment to untrusted traffic.

There are no published throughput benchmarks. The architecture is intended
to keep forwarding overhead low; capacity depends on the workload, kernel,
network and configuration.

## License

[Apache License 2.0](LICENSE).
