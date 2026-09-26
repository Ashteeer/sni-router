# Architecture

`sni-router` is a Linux proxy that selects a backend from the name in a TLS
ClientHello. A listener owns the accept addresses and route order; a backend
owns the forwarding mode, server pool and client-address forwarding policy.
Several listeners can use the same backend.

The default mode is TLS passthrough. The router reads enough of the handshake
to choose a destination, then forwards the original bytes. It does not need
the backend's private key. TLS termination is a separate, explicit backend
mode for HTTP or raw TCP services.

## Process model

At startup, the process creates one worker for each CPU reported by
`available_parallelism()`. Each worker attempts to pin itself to a CPU and
runs its own `monoio` runtime. Every worker binds its own TCP and UDP sockets
with `SO_REUSEPORT`; the kernel distributes connections and UDP flows among
them. A connection stays on the worker that accepted it.

The runtime uses `monoio::FusionDriver`: io_uring where available, with the
legacy driver as a fallback. Blocking a worker also blocks its other
connections, so TCP health probes, signal handling and certificate watching
run on separate system threads. The management API runs only on worker 0.
Some dependencies use Tokio utility types; the router does not start a Tokio
runtime for forwarding.

Routing configuration, backend pools and compiled ACLs form an immutable
`State` behind `ArcSwap`. Workers take a state snapshot when they need it.
Backend selection counters and metrics use shared atomics. The optional TCP
connection limit uses a sharded map keyed by client IP, updated on admission
and disconnect.

## TCP passthrough

```mermaid
flowchart LR
    Client --> Accept[Accept TCP]
    Accept --> Inspect[Read ClientHello]
    Inspect --> Route[ACL and first matching route]
    Route --> Connect[Choose and connect backend]
    Connect --> Replay[Optional PROXY header, then buffered bytes]
    Replay --> Splice[Bidirectional splice]
    Splice --> Backend
```

The TLS parser accepts a ClientHello split across reads and TLS records. It
does not require the complete handshake to arrive in one packet. Buffering is
bounded by `limits.max_client_hello`; reads while collecting the handshake
use `timeouts.handshake`. A missing SNI or non-TLS input is offered to a
`sni: "*"` route. Without a matching route, the connection closes.

After connecting, the router writes any configured PROXY protocol header,
replays the buffered client data and starts forwarding in both directions.
TCP passthrough uses nonblocking `splice(2)` calls through a kernel pipe in
each direction. Readiness waits return control to the runtime; bytes already
available can move without a userspace copy. If the environment refuses
splice before forwarding starts, that direction falls back to a reusable
userspace buffer.

`runtime.splice_chunk` is an upper bound on one move, not a minimum amount to
buffer. A one-byte message can be forwarded immediately. `pipe_size` controls
the staging pipe capacity, and `splice_spin` limits work before yielding to
other connections. `io_uring_entries` sizes each worker's ring. These settings
need workload measurements, not a blanket increase.

Established passthrough connections do not have an application idle deadline.
TCP keepalive is set on both legs through `timeouts.keepalive`; a quiet but
reachable peer can stay connected. The operating system supplies the probe
interval and retry count.

## UDP and QUIC

Each UDP accept socket keeps a flow table keyed by the client's IP and port.
The socket itself identifies the listener address, so the mapping represents
the client/server tuple. A routed flow owns a UDP socket connected to its
selected backend. The kernel rejects responses from other source addresses.

For QUIC v1 and v2, the router derives the public Initial keys, authenticates
and decrypts Initial packets, and reassembles CRYPTO data to read the TLS
ClientHello. This only exposes the Initial handshake; it does not give the
router access to application traffic. Subsequent datagrams use the flow
mapping and retain their original payload.

Datagrams that are not recognized as a supported QUIC Initial use the
catch-all route. This is how plain UDP services such as DNS are forwarded;
there is no DNS-name inspection. A failed Initial authentication is ignored
while the flow waits for a usable handshake.

Established flows reuse receive buffers. Plain UDP flows expire according to
`timeouts.udp_idle`; QUIC flows use `timeouts.idle`. There is a hard limit of
100,000 entries per accept socket, and the receive buffer currently accepts
at most 2,048 payload bytes per datagram. Larger datagrams are not supported
without truncation. These are implementation limits, not configuration
fields.

PROXY protocol has two different UDP wire formats in this implementation:

| Traffic | Header placement |
| --- | --- |
| Plain UDP | Prepended to every client-to-backend datagram |
| QUIC | Sent once as a separate leading datagram; QUIC payloads remain unchanged |

Enable this only when the backend explicitly supports the corresponding
format. A normal DNS or QUIC endpoint will not interpret it automatically.

## TLS termination and HTTP

`mode: terminate` uses rustls for client TLS. HTTP/1.1 requests are forwarded
to HTTP/1.1 backends, with optional forwarding headers and path rules. Body
framing supports Content-Length and chunked messages, with EOF-delimited
backend responses. See [known limitations](#known-limitations) for parsing gaps.
An HTTP/1.1 `101` response switches the
connection to a raw duplex tunnel for WebSocket and other upgrades.

Plaintext backend connections are acquired per request and returned to a
worker-local keepalive pool only after a complete response with a clean
message boundary. The pool keeps at most 32 idle connections per address per
worker, with a 30-second reuse age limit. Reuse checks and bounded retries
handle backends closing their own idle connections. A retry is not a general
guarantee that an arbitrary request can be replayed.

With `backend_tls`, the router instead establishes a TLS connection to the
backend, verifies its certificate and can present a client certificate for
mTLS. That TLS connection belongs to the client session and is reopened when
needed; it is not shared through the plaintext idle pool.

With `http2: true`, ALPN can select `h2`. Each HTTP/2 stream is translated to
an HTTP/1.1 request, using the same worker-local plaintext connection pool.
The connection advertises a limit of 128 concurrent streams. Backend TLS,
server push and trailer forwarding are not supported on this path.

`mode: terminate_tcp` only removes client TLS and forwards the decrypted byte
stream. It does not interpret HTTP, add HTTP headers or re-encrypt to the
backend. This is suitable for protocols such as DNS over TLS. The established
raw tunnel, like an upgraded HTTP tunnel, relies on TCP keepalive instead of
an application idle deadline.

`mode: redirect_https` receives plaintext HTTP and answers locally. Without
rules it redirects to the equivalent HTTPS URL; with rules it can also
return fixed responses. It never connects to a backend server.

## Backend selection

`round_robin` uses an atomic counter shared by all workers. `least_conn` uses
shared per-server connection counts for passthrough and raw TCP tunnels.
The per-request HTTP dialer does not maintain these counts, so `least_conn`
does not measure active HTTP/1.1 requests or HTTP/2 streams. Prefer
`round_robin` for HTTP termination.

TCP connections try eligible servers in the pool until one connects or all
candidates fail. With `health_check: true`, successful TCP probes mark servers
healthy, and failed connects mark them unhealthy. Healthy servers are tried
first. If those are exhausted, unhealthy servers are still tried: health
checks are a preference, not an absolute exclusion.

UDP chooses a server once per flow. It has no connect retry, health filtering
or per-server active-flow accounting for `least_conn`; use `round_robin`.
Health probes are TCP connects and do not establish UDP service health.

## Reload, restart and certificates

SIGHUP and the management API use the same configuration application logic.
Parsing or validation errors leave the running configuration in place.

| Change | Application method |
| --- | --- |
| Routes, ACLs, timeouts, limits and backend server pools | Atomic state replacement |
| API token only | Atomic state replacement |
| Listener identity, order, addresses, protocol or TCP socket options | Process re-exec |
| Termination mode/settings, TLS paths, HTTP headers or HTTP rules on a terminating backend | Process re-exec |
| `default_tls`, API bind/TLS, logging or runtime settings | Process re-exec |

A state replacement keeps established connections alive. Their routing
decision is retained; new connections use the new state. HTTP termination
looks up the current backend pool when acquiring a connection, so subsequent
requests on an existing client connection can use an updated server list.
Established UDP flows retain their selected backend.

Re-exec keeps the process ID but closes sockets and drops active connections.
It is also the mechanism behind SIGUSR1 and `POST /restart`. SIGTERM and
SIGINT request a drain, bounded by `timeouts.drain`.

Certificate file contents are a separate case: a watcher polls the effective
certificate/key files for terminating backends every five seconds and swaps
in successfully loaded keys for new handshakes. Renewing a certificate at the
same paths does not require re-exec. API certificates are loaded at startup
and need a restart. Certificate issuance stays with an external tool such as
certbot or lego.

## Boundaries

- This is a proxy, not a transparent source-IP-preserving packet router.
  Backends see the router's address unless they consume PROXY protocol or
  the configured HTTP forwarding headers.
- Backend destinations must be IP literals with ports. Runtime DNS
  resolution and hostname-based service discovery are not implemented.
- QUIC is passthrough only. Connection migration is not supported: the
  router cannot correlate new connection IDs announced inside encrypted
  application traffic. A migrated session may need to reconnect.
- Routing depends on a visible ClientHello name. An encrypted inner
  ClientHello is not decrypted; only the outer handshake can inform routing.
- `limits.max_conns_per_ip` counts TCP connections, not request rates, HTTP/2
  streams or UDP flows. There is no per-IP UDP quota. Capacity drops at the
  UDP flow-table limit do not currently have a dedicated metric.

## Known limitations

These implementation gaps are unresolved; the presence of a timeout or flow
count limit should not be read as a complete resource or protocol guarantee.

- Pending QUIC handshakes lack a strict total buffered-byte budget. Fragment
  accounting also does not fully bound reassembly metadata or repeated
  parsing work. Incomplete handshakes can consume excessive memory and CPU.
- HTTP/1.1 request framing does not consistently reject or normalize every
  ambiguous length/encoding combination. Differing parser decisions between
  the router and backend can cause request desynchronization.
- Informational HTTP responses and `Expect: 100-continue` are not fully
  handled by the termination gateway. Affected requests can stall until a
  timeout; this applies to both HTTP/1.1 and HTTP/2 clients.
- With backend `fast_open: true`, a connection failure can surface on the
  first write, after the normal connect retry/health-check path. Keep backend
  Fast Open disabled when relying on that retry behavior.

## Source map

| File | Responsibility |
| --- | --- |
| `src/main.rs`, `src/config/` | CLI, YAML schema, defaults and validation |
| `src/server.rs` | Workers, sockets, forwarding, pools, signals and reload |
| `src/protocol/` | TLS/QUIC inspection and PROXY protocol encoding |
| `src/router.rs`, `src/acl.rs`, `src/backend.rs` | Route matching, access control and server selection |
| `src/terminate.rs`, `src/redirect.rs` | TLS termination, HTTP handling and local responses |
| `src/admin.rs`, `src/metrics.rs`, `src/logging.rs` | Management API and observability |
| `src/update.rs` | Official release lookup, checksum verification and binary replacement |

See the [configuration reference](configuration.md) for field defaults and
the [example configurations](../config/examples/) for complete starting points.
