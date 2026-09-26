# Configuration reference

The router reads one UTF-8 YAML file. Listeners accept connections and select a
named backend; backends describe how those connections are forwarded. The
[routing guide](routing.md) explains the packet flow and gives examples of the
four backend modes.

## Load and validate a file

```sh
sni-router -t /etc/sni-router/sni-router.yaml
sni-router -c /etc/sni-router/sni-router.yaml
```

The config path comes from an explicit CLI path, then `SNI_ROUTER_CONFIG`, then
`/etc/sni-router/sni-router.yaml`. Paths inside the YAML are ordinary filesystem
paths: relative paths resolve from the process's working directory, not from
the config directory. Use absolute paths for certificates and keys. The YAML
loader does not expand environment variables or `~`.

Unknown fields, invalid enum values, and incorrect types are rejected. Once
the YAML has parsed, semantic validation reports multiple errors in one pass.
Exit status `0` means valid, including configurations with warnings. A nonzero
status means validation failed. `--no-color` or `NO_COLOR` disables diagnostic
colors; redirected output is also uncolored.

`-t` does not bind sockets or contact upstreams. It reads referenced certificate
files and, where available, Linux tuning settings. Add `--check-backends` to
attempt a **TCP** connection to every configured server address. That extra
check does not test UDP, QUIC, TLS, or application readiness.

```sh
sni-router -t /etc/sni-router/sni-router.yaml --check-backends
```

Validation does not prove that ports are free, certificate contents are usable,
or an upstream speaks the expected protocol. Permission-denied errors while
checking certificate files are warnings because the installed service can have
read capabilities that the invoking shell lacks.

## Top-level fields

| Field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `listeners` | list of listener objects | `[]` | Addresses, protocols, ACLs, and ordered routes. |
| `backends` | mapping of names to backend objects | `{}` | Forwarding modes and upstream servers. |
| `default_tls` | certificate object | absent | Shared client-facing certificate; also the API's TLS fallback. |
| `timeouts` | timeout object | values below | Durations, in whole seconds. |
| `limits` | limits object | values below | TCP resource limits. |
| `runtime` | runtime object | values below | Runtime and TCP splice settings. |
| `log` | logging object | `info`, `text` | Process and access-log output. |
| `api` | API object | absent | Management, metrics, and health endpoints. |

All top-level fields are optional individually. A file must provide at least
one listener or an `api` section. Once listeners exist, at least one backend
must exist and every route must reference a defined backend. An empty route
list is allowed with a warning; that listener drops all traffic.

An API-only starting point is valid:

```yaml
api:
  bind: "127.0.0.1:9000"
  token: "replace-with-a-long-random-token"
```

The installer creates an API-only configuration with generated credentials.
See [installation](installation.md) for its address and token handling.

## Listeners

```yaml
listeners:
  - name: https
    bind: ["0.0.0.0:443", "[::]:443"]
    proto: tcp
    routes:
      - { sni: "api.example.com", backend: api_service }
      - { sni: "*.example.com", backend: web }
      - { sni: "example.com", backend: web }
      - { sni: "*", backend: fallback }
```

This is a listener fragment; define the referenced backends in the same file.

| Field | Type | Default | Meaning and validation |
| --- | --- | --- | --- |
| `name` | string | required | Must be unique among listeners. |
| `bind` | list of strings | required | Nonempty list of literal `IP:port` addresses. IPv6 uses brackets, for example `[::]:443`. |
| `proto` | `tcp` or `udp` | `tcp` | `udp` accepts QUIC and ordinary UDP; it can only reference `passthrough` backends. |
| `routes` | list of route objects | required | Checked in order; first match wins. |
| `acl` | ACL object | absent | Client IP and server-name restrictions. |
| `backlog` | unsigned integer | `1024` | TCP accept queue length. Explicit `0` is an error. Ignored on UDP with a warning. |
| `fast_open` | boolean | `false` | Enables incoming TCP Fast Open. `true` on UDP is an error. |
| `fast_open_qlen` | unsigned integer | `1024` | Pending Fast Open queue length. Explicit `0` is an error; ignored with a warning when `fast_open` is false. |

Duplicate bind addresses for the same transport are rejected. A TCP listener
and a UDP listener may use the same address and port. Hostnames are not accepted
as bind addresses. Static validation does not detect every operating-system
bind conflict, such as a wildcard address overlapping a specific address, or a
data listener overlapping `api.bind`.

TCP queue lengths remain subject to `net.core.somaxconn`; validation warns when
the requested length exceeds it. The service logs its effective Fast Open
queue. The current validator expects `net.ipv4.tcp_fastopen=3` when incoming
Fast Open is enabled. Check [operations](operations.md) before changing host
tuning; larger queues do not substitute for measuring connection bursts.

### Routes

Each route has exactly two required string fields:

| Field | Meaning |
| --- | --- |
| `sni` | Exact server name, `*.example.com` suffix pattern, or `*` catch-all. Empty strings are rejected. |
| `backend` | Case-sensitive name of an entry in `backends`. |

Server-name matching is ASCII case-insensitive. `*.example.com` includes
`a.example.com` and `a.b.example.com`, but excludes `example.com`. Quote patterns
that start with `*` so YAML does not interpret them as aliases. Use these three
forms; this is not a regular-expression or general glob syntax.

Put specific names before broader patterns and the catch-all last. The
validator warns about shadowed routes, but its overlap check is case-sensitive,
so it does not catch every ordering mistake accepted by the runtime matcher.

Plain HTTP `Host` is **not** a route selector. Non-TLS TCP and plain UDP use the
catch-all. See [SNI, Host, and missing names](routing.md#sni-host-and-missing-names).

### ACLs

```yaml
acl:
  allow_ip: ["192.0.2.0/24", "2001:db8::/32"]
  deny_ip: ["192.0.2.25"]
  allow_sni: ["example.com", "*.example.com"]
  deny_sni: ["private.example.com"]
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `allow_ip` | list of IPs or CIDRs | `[]` | Empty permits any client IP; otherwise an entry must match. |
| `deny_ip` | list of IPs or CIDRs | `[]` | Any match rejects the client, even if an allow entry also matches. |
| `allow_sni` | list of name patterns | `[]` | Empty permits any name; otherwise an entry must match. |
| `deny_sni` | list of name patterns | `[]` | Any match rejects the name. Uses route matching rules. |

Both dimensions must pass. IP restrictions apply before reading the handshake;
name restrictions apply after inspection. A bare IP means a single host.
Prefixes must fit the address family (`0..32` for IPv4, `0..128` for IPv6).
IPv4 and IPv6 entries match their own family only.

Missing SNI is represented as an empty name. A nonempty `allow_sni` list blocks
such traffic unless it contains `*`; `deny_sni: ["*"]` rejects all names.
These ACLs apply to data listeners, not to the management API.

## Backends

```yaml
backends:
  web:
    mode: passthrough
    servers: ["192.0.2.10:443", "192.0.2.11:443"]
    balance: round_robin
    health_check: true
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | mode enum | `passthrough` | `passthrough`, `terminate`, `terminate_tcp`, or `redirect_https`. |
| `servers` | list of strings | `[]` | Literal upstream `IP:port` addresses. At least one is required except for `redirect_https`. DNS names are not supported. |
| `balance` | balance enum | `round_robin` | `round_robin` or `least_conn`; see limitations below. |
| `health_check` | boolean | `false` | Background TCP-connect checks. TCP dialing prefers healthy servers, then tries unhealthy ones if needed. |
| `fast_open` | boolean | `false` | TCP Fast Open on outgoing connections. Ignored for UDP and `redirect_https`. |
| `proxy_protocol` | `none`, `v1`, or `v2` | `none` | Sends client address metadata to a compatible upstream. |
| `tls` | certificate object | absent | Client-facing certificate for either TLS termination mode. Falls back to `default_tls`. |
| `backend_tls` | backend TLS object | absent | TLS on the upstream side of HTTP `terminate`. |
| `headers` | header object | all false | HTTP forwarding headers for `terminate`. |
| `http2` | boolean | `false` | Offers `h2` ALPN in `terminate`; translates requests to upstream HTTP/1.1. |
| `http_rules` | list of HTTP rule objects | `[]` | Ordered path rules in `terminate` or `redirect_https`. |

Listener and upstream address families are independent. An IPv6 client may
reach an IPv4 upstream and vice versa.

### Mode applicability

| Setting or behavior | `passthrough` | `terminate` | `terminate_tcp` | `redirect_https` |
| --- | --- | --- | --- | --- |
| Client transport | TCP or UDP | TLS over TCP | TLS over TCP | Plain HTTP over TCP |
| Upstream payload | Original stream/datagrams | HTTP/1.1, optionally TLS | Decrypted TCP bytes | No upstream |
| `servers` | Required | Required, even with only synthetic rules | Required | Ignored |
| `tls` / `default_tls` | Not used for data | Required | Required | Not used for data |
| `backend_tls` | Ignored | Supported unless `http2: true` | Ignored | Ignored |
| `proxy_protocol` | Supported | Ignored | Supported | Ignored |
| `headers` | Ignored | Supported | Ignored | Ignored |
| `http2` | Not interpreted | Supported | Ignored | Ignored |
| `http_rules` | Ignored | Supported | Ignored | Supported; no forwarding |

Some ignored combinations produce warnings, not errors. For example,
`http2: true` outside `terminate` warns, while combining `http2: true` with
`backend_tls` in `terminate` is an error. An ignored setting is not evidence
that the requested behavior is supported.

`least_conn` counts live TCP passthrough and `terminate_tcp` connections across
workers. HTTP termination and UDP flows do not currently update those counts;
use `round_robin` for those paths. TCP connect failures try other pool members.
Health checks are TCP-connect checks only: UDP selection does not consult their
results or retry other servers. Do not enable them for UDP-only backends.

Outgoing Fast Open defers part of connection establishment until the first
write, which can move failures outside the normal connect-time retry path. Keep
it disabled unless that trade-off is acceptable; loopback upstreams have no
meaningful round-trip saving.

For framing and receiver requirements, see
[PROXY protocol](routing.md#preserving-client-addresses).

## TLS certificates

The same certificate object is accepted by `default_tls`, `backends.<name>.tls`,
and `api.tls`:

```yaml
default_tls:
  cert: /etc/letsencrypt/live/example.com/fullchain.pem
  key: /etc/letsencrypt/live/example.com/privkey.pem
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cert` | path string | required | PEM certificate chain, leaf certificate first. |
| `key` | path string | required | PEM private key. |

A backend's own `tls` object replaces the shared object completely. Omitting
`tls` uses `default_tls`; omitting both is invalid for `terminate` and
`terminate_tcp`. These modes do not require client certificates.

For data backends, the certificate watcher checks the certificate file's
modification time every five seconds and reloads its certificate/key pair.
Renewals must update the certificate file; changing only the key file does not
trigger the watcher. Existing connections continue using their established
TLS session. Use an external ACME client such as certbot or lego; there is no
built-in ACME client.

The API uses `api.tls`, then `default_tls`, then plaintext HTTP. Adding
`default_tls` therefore also enables HTTPS on an API that has no explicit
`api.tls`. API certificates and upstream TLS credentials are loaded at startup;
they do not use the data-certificate watcher. See [operations](operations.md)
for renewal and restart procedures.

### Upstream TLS: `backend_tls`

An empty object, `backend_tls: {}`, enables upstream TLS with built-in trust
roots and the client's SNI. Omitting the object sends plaintext HTTP/1.1.

```yaml
backend_tls:
  sni: origin.example.com
  ca: /etc/sni-router/origin-ca.pem
  client_cert: /etc/sni-router/client.pem
  client_key: /etc/sni-router/client-key.pem
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `sni` | string | client's inspected SNI | Name used for upstream TLS and certificate verification. Set explicitly when the origin has a different name or the client has no SNI. |
| `ca` | path string | built-in WebPKI roots | PEM trust bundle. Replaces the built-in roots. |
| `client_cert` | path string | absent | PEM client certificate chain for upstream mutual TLS. |
| `client_key` | path string | absent | PEM client key; must be set together with `client_cert`. |
| `insecure_skip_verify` | boolean | `false` | Disables upstream certificate chain/name verification; validation emits a warning. Use a trust bundle for private CAs. |

This section only affects `mode: terminate`. It does not add TLS to
`passthrough` or `terminate_tcp`, and cannot be combined with `http2: true`.

## HTTP forwarding headers

```yaml
headers:
  x_real_ip: true
  x_forwarded_for: true
  x_forwarded_proto: true
```

Each field is boolean and defaults to `false`:

| Field | Generated value | Existing client header |
| --- | --- | --- |
| `x_real_ip` | Client socket IP address | Replaced. |
| `x_forwarded_for` | Client socket IP address | The router appends its observed IP after the supplied value. |
| `x_forwarded_proto` | `https` | Replaced. |

These fields work only in HTTP `terminate`, including HTTP/2 requests translated
to HTTP/1.1. The observed IP is the direct socket peer; the router does not
consume an incoming PROXY header. Existing `X-Forwarded-For` values are
untrusted client input. An upstream that needs one trusted client address
should use the overwritten `X-Real-IP`, or explicitly configure how it trusts
the rightmost added address.

## HTTP path rules

Rules apply after TLS termination, or in the plaintext `redirect_https`
responder. They act within the backend already selected by SNI; a rule cannot
select another backend.

```yaml
http_rules:
  - path: /dns-query
    action: forward
  - path: /old
    action: redirect
    status: 308
    to: https://example.com/new
  - path: "*"
    action: respond
    status: 404
    content_type: text/plain
    body: "not found\n"
```

| Field | Type | Default | Meaning and validation |
| --- | --- | --- | --- |
| `path` | string | required | Nonempty, case-sensitive prefix, or `*`. First match wins. |
| `action` | `forward`, `respond`, or `redirect` | required | Forward upstream, generate a response, or generate a redirect. |
| `status` | unsigned integer | action-dependent | Required for `respond`, range `100..599`. Optional for `redirect`, default `301`, range `300..399`. Ignored with a warning for `forward`. |
| `body` | string | `""` | UTF-8 response body for `respond`; ignored for other actions. |
| `content_type` | string | `text/plain` | Response `Content-Type` for `respond`; ignored for other actions. |
| `to` | string | absent | Required for `redirect`: `https` or an absolute URL. Ignored for other actions. |

Prefix matching does not recognize path segments or regular expressions:
`/api` also matches `/apix`. HTTP/1.1 matches the request target as received,
including its query string; the HTTP/2 gateway matches the URI path without the
query. Prefer path-only prefixes for consistent behavior.

In `terminate`, empty rules or no matching rule forwards the request. In
`redirect_https`, empty rules produce a `301` HTTPS redirect; once rules exist,
no match produces `404`. A `forward` rule in `redirect_https` also produces
`404`, since that mode has no upstream.

`to: https` builds `https://` plus the received Host/authority and request
target. It preserves an explicit port in the host value; it does not translate
`:80` to `:443`. A literal URL is used unchanged. The validator only checks for
the literal `https` or the presence of `://`; it is not a complete URL parser.
The HTTP/2 synthetic redirect currently uses the URI path without its query.
Use a literal destination for a fixed canonical hostname or port. Avoid an
HTTPS-upgrade rule on an already-HTTPS endpoint unless the resulting redirect
is intentional.

## Timeouts

All values are nonnegative YAML integers in **seconds**; duration strings such
as `5s` are not accepted. Every field except `keepalive` must be greater than
zero. Values above `86400` warn. A `udp_idle` above `300` also warns because each
flow holds an upstream socket.

| Field | Default | Current scope |
| --- | --- | --- |
| `handshake` | `5` | Timeout for each TCP read while inspecting the ClientHello; also supplies TCP deferred-accept tuning. It is not a total handshake deadline. |
| `connect` | `10` | Timeout per upstream TCP connection attempt and per health probe. Trying multiple servers may take multiple such intervals. |
| `idle` | `300` | HTTP/1.1 reads, HTTP/1.1 upstream reads for HTTP/2 clients, initial TLS/HTTP/2 handshakes, and QUIC flow expiry. Not a TCP passthrough or established raw-tunnel idle limit. |
| `udp_idle` | `30` | Plain UDP flow expiry, separate from QUIC. |
| `keepalive` | `60` | TCP keepalive idle interval on client and upstream sockets; `0` disables it. Probe count and interval remain kernel settings. |
| `health_interval` | `10` | Sleep between background TCP health-check passes. Probe duration adds to the pass time. |
| `drain` | `30` | Grace period before exit after `SIGTERM` or `SIGINT`. |

Passthrough, raw TLS tunnels, and upgraded WebSocket tunnels have no application
idle deadline. TCP keepalive detects unreachable peers; it does not close a
quiet peer that still answers probes. Covered HTTP reads use separate idle
waits rather than an overall request deadline. Waiting for a new HTTP/2 stream
or request-body data from an HTTP/2 client has no separate idle deadline.

UDP expiry is based on activity from the client, with a separate timeout on the
upstream receive task. A stream of replies alone does not refresh the main
flow-table timestamp. Details and other UDP restrictions are in
[the routing guide](routing.md#udp-and-quic).

## Limits

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_client_hello` | unsigned integer, bytes | `16384` | TLS ClientHello inspection limit on TCP. Below `512` is an error; above `1048576` warns. |
| `max_conns_per_ip` | unsigned integer | `0` | Concurrent TCP connections per observed client IP across workers. `0` means unlimited. |

The per-IP limit is a concurrency cap, not requests per second. It does not
limit UDP flows or API connections. `max_client_hello` does not bound UDP pending
datagrams: QUIC uses a separate internal reassembly limit. Neither setting is
a global memory quota.

## Runtime

The defaults are suitable starting values. These fields change how workers
wait for I/O and forward TCP passthrough traffic; they do not delay forwarding
until a buffer fills.

```yaml
runtime:
  io_uring_entries: 4096
  splice_chunk: 65536
  pipe_size: 65536
  splice_spin: 8
```

| Field | Type | Default | Meaning and validation |
| --- | --- | --- | --- |
| `io_uring_entries` | unsigned integer | `4096` | Submission queue entries per worker. `0` and values above `32768` are errors. Below `256` warns and is raised by the runtime. Non-powers of two warn and are rounded up by the kernel. |
| `splice_chunk` | unsigned integer, bytes | `65536` | Maximum bytes moved in one passthrough splice operation. `0` is an error. Below `4096` or above the configured pipe size warns. |
| `pipe_size` | unsigned integer, bytes | `65536` | Requested capacity of each staging pipe. `0` leaves the kernel default. Values below `4096` or above the host pipe limit warn. |
| `splice_spin` | unsigned integer | `8` | Forwarding rounds before yielding to other tasks. `0` behaves like `1`; above `64` warns. |

For 1 MiB of data in one direction, full 64 KiB moves take 16 forwarding rounds;
each round moves socket-to-pipe, then pipe-to-socket. The former 4 KiB forwarding loop
needed 256 rounds and 512 io_uring waits for the same amount of data. The current
forwarder issues nonblocking splice syscalls directly and uses io_uring for
readiness waits, so its number of ring waits depends on socket readiness rather
than a fixed number per chunk. Actual move sizes can be smaller than the cap.

Each spliced connection uses two pipes. Enlarging them consumes more of the
per-user pipe-page allowance; once that allowance is reached, the kernel may
shrink newly allocated pipes. A request above `fs.pipe-max-size` may be refused,
leaving the default capacity. Inspect startup logs for the effective capacity.

An edit to any `runtime` field requires a process restart when applied. The
[architecture guide](architecture.md) describes the worker model and buffered
fallback when splice cannot be used.

## Logging

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `level` | string | `info` | `error`, `warn`, `info`, `debug`, or `trace`; case-insensitive, with `warning` also accepted. A bare `RUST_LOG` level overrides it at startup. |
| `format` | `text` or `json` | `text` | Human-readable text or one JSON object per line. |

```yaml
log:
  level: info
  format: json
```

See [operations](operations.md) for access-log fields and metrics. Debug logging
includes HTTP request details; choose an appropriate level for the data being
handled.

## Management API

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `bind` | string | required when `api` exists | One literal `IP:port` address. |
| `token` | string | absent | Bearer credential for every endpoint when set. Never serialized by `GET /config`. |
| `tls` | certificate object | absent | Explicit HTTPS certificate; otherwise inherits `default_tls`, or uses HTTP if neither exists. |

Without a token, read endpoints are accessible to anyone who can reach the
address and write endpoints return `403`. Set a nonempty token for management
access. Non-loopback access without a token produces a validation warning.
Use HTTPS or a protected tunnel when the API crosses an untrusted network.

The single API listener serves health, status, configuration, updates, and
Prometheus metrics. There are no separate `admin` or `metrics` top-level
sections; those obsolete keys are rejected. See the [API reference](api.md)
for endpoints, authentication, and configuration updates. A redacted
`GET /config` response is not a complete credential-preserving backup.

## Applying changes

Reload validates the new configuration before changing the active state. A
valid change may still need a process restart. `SIGHUP` and the API use the same
decision:

| Change | How it is applied |
| --- | --- |
| Routes, ACLs, limits, timeouts, upstream addresses, balancing, health checks, outgoing Fast Open | State swap for subsequent work; existing connections can retain their earlier settings. |
| Listener names/order, bind addresses, protocol, accept queues, incoming Fast Open | In-place process restart. |
| Adding/removing a terminating backend; its mode, TLS paths, upstream TLS, headers, HTTP/2, or HTTP rules | In-place process restart. |
| `default_tls`, API bind/TLS, logging, runtime | In-place process restart. |
| API token alone | State swap. |
| Plaintext `redirect_https` HTTP rules | State swap. |
| Data certificate renewal at the same path | Certificate watcher; no config reload required. |

An in-place restart keeps the process ID but disconnects active clients. A
reload is therefore not a promise of uninterrupted service for every config
edit. Existing UDP flows keep their selected upstream until expiry. See
[operations](operations.md) for validation, reload, restart, and backup commands.

The schema and validation implementation are in
[`src/config/mod.rs`](../src/config/mod.rs) and
[`src/config/validate.rs`](../src/config/validate.rs).
