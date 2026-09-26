# Routing and protocol behavior

sni-router selects a backend from the server name in the client's initial
handshake. In passthrough mode the upstream completes TLS with the client;
the router does not need that service's certificate or private key. Termination
modes make the router the client's TLS endpoint instead.

Use the [configuration reference](configuration.md) for every field and default,
or start from the [configuration examples](../config/examples/).

## SNI, Host, and missing names

A listener's route list is evaluated from top to bottom. The first matching
rule wins, even if a later rule is more specific.

```yaml
routes:
  - { sni: "api.example.com", backend: api }
  - { sni: "*.example.com", backend: web }
  - { sni: "example.com", backend: web }
  - { sni: "*", backend: fallback }
```

| Client name | Selected backend | Reason |
| --- | --- | --- |
| `api.example.com` | `api` | Exact rule is first. |
| `WWW.EXAMPLE.COM` | `web` | Names are matched case-insensitively. |
| `a.b.example.com` | `web` | A suffix wildcard includes deeper subdomains. |
| `example.com` | `web` | The apex needs its own rule. |
| `other.example.net` | `fallback` | Catch-all. |
| No usable SNI | `fallback` | Only the catch-all matches a missing name. |

The name comes from a TLS ClientHello over TCP or a supported QUIC Initial
over UDP. Plain HTTP `Host` does not select a backend. An HTTP request sent to
a TCP listener has no TLS SNI and therefore needs `sni: "*"`, even if its Host
looks like an exact route. The Host/authority is used later when constructing
an HTTP redirect; it does not redo the listener's selection.

No matching route means the TCP connection closes or the UDP flow is discarded.
There is no implicit default backend. A catch-all also permits unknown names
and non-TLS traffic, so include it only when the selected backend should receive
those connections.

Routing requires a visible name. Encrypted ClientHello's inner name cannot be
read by a passthrough router; any visible outer name determines the route.
TCP protocols whose server sends the first application bytes are not suitable:
the router waits for client data before choosing an upstream.

## TCP passthrough

```yaml
listeners:
  - name: tls
    bind: ["0.0.0.0:443"]
    routes:
      - { sni: "app.example.com", backend: app }

backends:
  app:
    mode: passthrough
    servers: ["127.0.0.1:8443"]
```

The router buffers enough of the ClientHello to read SNI, picks a server,
optionally writes a PROXY header, and replays the buffered bytes unchanged.
Subsequent stream data is forwarded in both directions using splice where
available, with a buffered fallback. The upstream presents the certificate and
negotiates TLS and ALPN directly with the client. HTTP/2, WebSocket, and other
application protocols remain opaque on this path.

The parser handles ClientHello data split across TCP reads and TLS records.
TCP ordering and retransmission are provided by the operating system. This does
not imply that arbitrary modified handshakes are accepted: routing still needs
a parsable ClientHello or a catch-all.

`timeouts.handshake` limits each inspection read; `limits.max_client_hello`
limits TCP ClientHello inspection. Once forwarding starts, `timeouts.idle` does
not expire the passthrough connection. TCP keepalive handles unreachable peers,
but quiet reachable peers can stay connected indefinitely.

For a non-TLS, client-first protocol, use a catch-all and point `servers` to a
compatible TCP service. The router does not convert protocols.

## TLS termination for HTTP

```yaml
listeners:
  - name: https
    bind: ["0.0.0.0:443"]
    routes:
      - { sni: "app.example.com", backend: app }

default_tls:
  cert: /etc/letsencrypt/live/app.example.com/fullchain.pem
  key: /etc/letsencrypt/live/app.example.com/privkey.pem

backends:
  app:
    mode: terminate
    servers: ["127.0.0.1:8080"]
    headers:
      x_real_ip: true
      x_forwarded_proto: true
```

The route is chosen from SNI before the TLS handshake is completed. The router
presents the selected backend's certificate, then forwards HTTP/1.1 to that
backend's servers. The request Host is preserved. It neither selects a second
backend nor has to equal the SNI for routing to succeed.

HTTP keep-alive connections can carry multiple requests. Plaintext upstream
connections are reused from per-worker pools when a complete response has been
read and the connection is reusable. Upstream TLS is available through
`backend_tls`; it verifies certificates by default and can present a client
certificate for mutual TLS.

An HTTP/1.1 `101` Upgrade response switches the connection into a byte tunnel,
including data already buffered on either side. This supports WebSocket over
the HTTP/1.1 termination path. The upgraded tunnel has no application idle
deadline.

### HTTP/2

Add `http2: true` to a `terminate` backend to offer `h2` and `http/1.1` through
ALPN. A client that negotiates h2 uses an HTTP/2-to-HTTP/1.1 gateway. Concurrent
streams can use separate upstream connections, and reusable plaintext
connections return to the worker's idle pool.

The gateway has these boundaries:

- Upstreams speak plaintext HTTP/1.1. Combining `http2` and `backend_tls` is rejected.
- No HTTP/2 server push or trailer forwarding is provided.
- The advertised maximum is 128 concurrent streams per client connection.
- `least_conn` does not count HTTP streams or HTTP termination's pooled upstream connections; use `round_robin`.
- HTTP/1.1 Upgrade support does not imply HTTP/2 extended CONNECT support.

TLS and HTTP termination are narrower than a general-purpose HTTP proxy. In
particular, handling of interim `1xx` responses, `Expect: 100-continue`, and
ambiguous HTTP/1.1 framing still needs hardening. Test the application's request
patterns before placing this mode in front of it. TCP passthrough leaves HTTP
parsing to the upstream.

### Path rules

`http_rules` can forward to the selected backend, return a fixed response, or
redirect. They do not route to another named backend.

```yaml
http_rules:
  - { path: /dns-query, action: forward }
  - { path: "*", action: respond, status: 404, body: "not found\n" }
```

Rules are ordered, case-sensitive prefix matches. This example also forwards
`/dns-query/extra` and `/dns-query-other`; it is not an exact-path matcher. No
matching rule in `terminate` means normal forwarding. Add a final catch-all
response when other paths should be refused. Refer to the
[HTTP rule fields](configuration.md#http-path-rules) for redirects and the
HTTP/1.1 versus HTTP/2 query-string distinction.

## TLS termination for raw TCP

`terminate_tcp` removes client TLS and forwards the decrypted stream without
HTTP parsing. A DNS-over-TLS frontend is one use:

```yaml
listeners:
  - name: dot
    bind: ["0.0.0.0:853"]
    routes:
      - { sni: "dns.example.com", backend: dns }

default_tls:
  cert: /etc/letsencrypt/live/dns.example.com/fullchain.pem
  key: /etc/letsencrypt/live/dns.example.com/privkey.pem

backends:
  dns:
    mode: terminate_tcp
    servers: ["127.0.0.1:53"]
```

The upstream must accept the decrypted TCP protocol. For DoT this means DNS over
TCP, including its length framing. The router does not translate DNS messages
to UDP. It does not force HTTP ALPN, inspect HTTP headers, or apply path rules.
`backend_tls` is ignored: the upstream leg is plaintext.

PROXY protocol can be prepended if the upstream supports it. The client-facing
TLS handshake uses `timeouts.idle`; the established raw tunnel has no
application idle deadline.

## Plain HTTP redirects and responses

```yaml
listeners:
  - name: http
    bind: ["0.0.0.0:80"]
    routes:
      - { sni: "*", backend: redirect }

backends:
  redirect:
    mode: redirect_https
```

`redirect_https` reads a plaintext HTTP request and responds without contacting
an upstream. With no `http_rules`, it returns `301` to the received host and
request target with an `https://` scheme. Missing Host or an unsuitable request
target yields `400`.

The mode works on any configured TCP port; the example uses 80 by convention.
It answers one request and closes. It preserves a port explicitly supplied in
Host, so use a literal redirect URL when the destination port must change.

Add `http_rules` to provide fixed responses or custom redirects. When rules are
present, an unmatched path returns `404`. `forward` also returns `404` in this
mode because there is no upstream. HTTP host-based virtual routing and a
general plaintext HTTP reverse-proxy mode are not implemented.

## UDP and QUIC

```yaml
listeners:
  - name: quic
    bind: ["0.0.0.0:443"]
    proto: udp
    routes:
      - { sni: "app.example.com", backend: quic_app }

backends:
  quic_app:
    mode: passthrough
    servers: ["127.0.0.1:8443"]
```

UDP listeners support passthrough only. For QUIC v1 and v2 Initial packets, the
router derives the public Initial keys, decrypts the Initial payload, and
reassembles CRYPTO fragments to inspect the ClientHello. It does not possess
application traffic keys or terminate QUIC. HTTP/3 remains an upstream concern.

Once a route is known, a flow binds that client address and port to one upstream
address. Later datagrams use the stored selection. Datagrams that arrive while
the Initial is being inspected are queued for replay. Undecryptable Initial-like
packets do not supply a name; the router keeps waiting for a usable handshake.

For ordinary UDP such as DNS, use `sni: "*"`. There is no TLS name to inspect.
Packets not recognized as a supported Initial also use the missing-name path.
The router preserves datagram boundaries and uses a connected UDP socket toward
the upstream, so replies are accepted from that selected upstream only.

TCP and UDP listeners may bind the same IP and port, for example DNS on port 53
or HTTPS/HTTP/3 on port 443. Define separate listeners because each has its own
transport and flow behavior.

### UDP boundaries

- QUIC connection migration is not supported. A changed client address or port creates a different flow; new encrypted connection IDs cannot be mapped to the old flow without backend cooperation.
- UDP uses one upstream per flow. It has no TCP health filtering, retry, or meaningful `least_conn` accounting.
- Plain UDP expires with `timeouts.udp_idle`; QUIC uses `timeouts.idle`. Client activity refreshes the flow timestamp; upstream-only traffic does not.
- A fixed cap of 100,000 flows applies to each worker's bound UDP socket. This is not a process-wide connection limit or a configurable memory budget.
- Pending Initial datagrams and reassembly bookkeeping do not yet have complete per-flow memory bounds. `limits.max_client_hello` and `max_conns_per_ip` only protect TCP; they do not solve UDP memory exhaustion.

A reply task also stops after its upstream receive timeout. The flow-table
expiry check runs during receive processing. These details matter for one-way
traffic or clients that remain silent for long periods. UDP sends and routing
work currently run in the same receive loop, so slow forwarding can delay other
flows on that worker.

## Preserving client addresses

Upstreams ordinarily see the router's source address. Choose metadata support
according to the upstream protocol:

| Path | Available metadata | Framing |
| --- | --- | --- |
| TCP `passthrough` | PROXY v1 or v2 | One header before the original client bytes. |
| `terminate_tcp` | PROXY v1 or v2 | One header before the decrypted stream. |
| HTTP `terminate` | Configured `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` | HTTP headers; `proxy_protocol` is ignored here. |
| Plain UDP | PROXY framing, preferably v2 | Header prepended to every client datagram. |
| QUIC | Separate leading PROXY datagram | Initial and subsequent QUIC datagrams stay unchanged. |

Leave `proxy_protocol: none` unless the upstream explicitly understands the
chosen format. TCP services expecting a TLS record or application bytes first
will fail if a PROXY header appears unexpectedly.

PROXY v1 has TCP address syntax; use v2 for a receiver expecting datagram
metadata. A normal QUIC server does not learn the client IP merely because it
receives a separate PROXY datagram. That convention needs receiver support;
otherwise keep it disabled. Replies do not have PROXY headers removed by the
router.

The router does not accept an incoming PROXY header from another proxy. ACLs,
connection limits, and generated metadata use the directly observed socket
peer. HTTP `X-Forwarded-For` appends to a client-supplied value; see
[header trust behavior](configuration.md#http-forwarding-headers) before using it
for application access controls.

## Balancing, failure, and reload

`round_robin` rotates through pool members. `least_conn` chooses the least-used
counted TCP server; ties favor the first candidate. Counts are shared across
workers for TCP passthrough and raw termination, but not for HTTP termination
or UDP flows.

TCP dialing tries other servers after a connection failure. With
`health_check: true`, it prefers servers passing background TCP probes, then
tries the remaining servers if the healthy set is exhausted. The policy fails
open: an unhealthy mark is not an absolute ban. It does not retry a live
passthrough stream on another server after application data has begun.

A route or upstream-list reload affects subsequent selections. Existing TCP
connections and UDP flows are not moved to different upstreams. HTTP
termination can select from the current pool when opening an upstream
connection for a later request. Changes to listeners or TLS termination setup
can trigger an in-place restart and close active connections. Use the
[reload table](configuration.md#applying-changes) when planning an edit.
