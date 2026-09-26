# Operations

The examples below use the [systemd installation](installation.md). Validate
configuration changes before applying them, and inspect the journal after a
reload: some changes require a restart and disconnect active clients.

## Command line

| Command | Behavior |
|---|---|
| `sni-router` | Run with the resolved configuration path |
| `sni-router -c /path/config.yaml` | Run with an explicit configuration |
| `sni-router -t [PATH]` | Parse and validate, then exit without opening listeners |
| `sni-router -t --check-backends` | Also attempt TCP connections to every configured backend address |
| `sni-router -u [--force]` | Install the latest official release; no configuration is needed |
| `sni-router -v` / `-V` / `--version` | Print the compiled version |
| `sni-router --no-color` | Disable colored CLI diagnostics |
| `sni-router -h` / `--help` | Print command-line help |

The long forms are `--config`, `--test-config`, and `--update`. Configuration
path precedence is an explicit argument, then `SNI_ROUTER_CONFIG`, then
`/etc/sni-router/sni-router.yaml`. `NO_COLOR` disables colored validation output.

Validation exits with `0` for a valid configuration, including one with
warnings, and `1` for load or validation errors. An unrecognized CLI argument
returns `2`. The installer makes the configuration readable only by its owner;
use `sudo sni-router -t` for that installation.

The static check validates the schema, routing references, addresses, and
certificate file accessibility. It does not bind ports, contact backends,
complete TLS handshakes, or prove that runtime certificate loading will
succeed. `--check-backends` adds a three-second TCP connect attempt per server,
only after static validation succeeds. It also probes servers used by UDP
listeners over TCP; it is not a UDP or application health check.

## Reload and restart

Back up the file, edit it, and validate it before reload:

```bash
sudo cp -a /etc/sni-router/sni-router.yaml /etc/sni-router/sni-router.yaml.bak
sudoedit /etc/sni-router/sni-router.yaml
sudo sni-router -t && sudo systemctl reload sni-router
sudo journalctl -u sni-router -n 30 --no-pager
```

`systemctl reload` sends `SIGHUP`. The signal handler reads and validates the
file. Invalid configurations leave the running state intact and produce a log
entry. The command's successful exit only means that systemd sent the signal;
check the logs or API to confirm that the configuration was applied.

| Change | Application |
|---|---|
| Routes, ACLs, backend server lists and balancing, timeouts, limits | Hot reload |
| Only `api.token` | Hot reload; new requests must use the new token |
| Listener identity/order, bind addresses, protocol, Fast Open or queue settings | Process re-exec |
| Termination contexts: mode, certificates, upstream TLS, headers, HTTP/2, HTTP rules; `default_tls` | Process re-exec |
| API listener/TLS, logging, or any `runtime` setting | Process re-exec |

Changes to `http_rules` on a `redirect_https` backend can be hot-reloaded;
the restart requirement above applies to rules held in a TLS termination
context. Creating or removing such a context also requires a restart.

A hot reload preserves active connections. Existing TCP sessions can retain
settings from their original configuration; new sessions use the new state.
Already routed UDP flows retain their backend until they expire. Terminated
HTTP requests use a shared backend dialer, so later backend selections can pick
up a changed pool during an existing client session.

A re-exec reloads the executable at the same PID, closes sockets, and binds them
again. It **drops active connections without draining**. New binds or TLS
loading can still fail after static validation; inspect startup logs and test
traffic after a structural edit. `PUT /config` and `POST /reload` report which
path was selected; see the [API reference](api.md).

| Signal / command | Behavior |
|---|---|
| `SIGHUP` / `systemctl reload sni-router` | Validate and hot-reload or re-exec as required |
| `SIGUSR1` | Validate the file, then force immediate re-exec |
| `SIGTERM` / `SIGINT` | Stop admitting new TCP work, wait for tracked active TCP connections, then exit |
| `systemctl restart sni-router` | Stop and start through systemd; normally includes the drain period |

For an immediate restart under systemd:

```bash
sudo systemctl kill --kill-whom=main --signal=SIGUSR1 sni-router
```

`timeouts.drain` defaults to 30 seconds. Shutdown exits when the active TCP
gauge reaches zero or the deadline expires. It does not implement a separate
UDP/QUIC drain or an HTTP/2 GOAWAY procedure. If you increase the drain period,
ensure systemd's `TimeoutStopSec` allows it to finish.

## Certificate renewal

Use an external ACME client such as certbot or lego to issue and renew
certificates. sni-router does not issue certificates itself. Point `tls` or
`default_tls` at the maintained PEM files; see the
[TLS examples](configuration.md).

For `terminate` and `terminate_tcp` backends, a watcher checks the certificate
file's modification time every five seconds. When it changes, the watcher
loads the certificate and key together and swaps the certificate for new
handshakes. Existing connections continue. A load failure keeps the old
certificate and is logged.

The watcher observes the **certificate file**, not the key file independently.
Install a matching certificate/key pair during renewal. Updating only the key
does not trigger a reload.

The management API has no certificate watcher, including when it inherits
`default_tls`. Restart after renewing its certificate. Sending `SIGHUP` with
an unchanged configuration does not reload the API's TLS context. A restart
also reloads upstream TLS client credentials and trust configuration.

The installer grants `CAP_DAC_READ_SEARCH` so the service can read root-owned
certificate files. A manual foreground run does not inherit that capability.
Permission warnings from an unprivileged `-t` check therefore need to be
interpreted in the context of the account that actually runs the service.

## Timeouts and resource use

All configured timeout values are seconds.

| Setting | Default | Current behavior |
|---|---:|---|
| `handshake` | 5 | Timeout for each read while collecting the TCP ClientHello; not a total handshake deadline |
| `connect` | 10 | Backend TCP connection attempt timeout |
| `idle` | 300 | HTTP/1.1 reads, HTTP/1.1 upstream reads for h2 clients, initial TLS/h2 handshakes; QUIC flow expiry |
| `udp_idle` | 30 | Plain UDP flow expiry |
| `keepalive` | 60 | TCP keepalive idle period on both legs; `0` disables it |
| `health_interval` | 10 | Interval between TCP backend health-check passes |
| `drain` | 30 | Maximum wait for tracked active TCP connections at shutdown |

Established TCP passthrough, raw TLS-terminated tunnels, and upgraded WebSocket
tunnels have no application idle deadline. TCP keepalive detects an unreachable
peer, but does not expire a quiet peer that still answers probes. Keepalive
probe interval and retry count come from the host's TCP settings. Waiting for
new HTTP/2 streams or request-body data from an HTTP/2 client is not covered
by a separate idle deadline.

UDP flow expiry currently uses client-to-router activity for the table sweep.
A stream of backend replies alone does not keep that table entry alive. Each
flow consumes a backend socket. The flow cap is 100,000 per worker listener
socket; there is currently no metric for drops at that cap.

`limits.max_conns_per_ip` limits simultaneous TCP connections. It is not a
requests-per-second limit and does not cap UDP flows or individual HTTP/2
streams. HTTP/2 advertises a limit of 128 concurrent streams per connection.

Start with the `runtime` defaults. Each passthrough connection uses two pipes;
increasing `pipe_size` increases its kernel memory budget. The per-user
`fs.pipe-user-pages-soft` limit can cause the kernel to shrink new pipes. Check
validation warnings and the `data path ready` log, which reports effective
pipe sizing. See the [configuration reference](configuration.md#runtime) for runtime
options and ranges.

## Logs

```bash
sudo journalctl -u sni-router -f
```

Set the format and level in configuration:

```yaml
log:
  level: info
  format: json
```

Access events include the peer, SNI, backend and mode. TCP close events include
duration; passthrough/raw tunnel paths report byte counts, while HTTP
termination reports `requests`, `upgraded`, and `error`. UDP emits an event
when a flow is routed. Connections rejected before routing do not all produce
an access event, and connection logs are not per-request HTTP logs.

`debug` enables router diagnostics while keeping noisy dependency frame logs
at INFO. `trace` includes dependency detail and can produce substantial output.
A bare `RUST_LOG=debug` overrides the configured level at process startup;
module filter expressions such as `sni_router=debug` are not supported. Log
configuration changes require re-exec.

## Metrics

`GET /metrics` uses the same address, TLS settings, and bearer token as the
management API. Metrics are Prometheus text, not a separate exporter service.
For a loopback API on port 9000, a Prometheus job can use:

```yaml
scrape_configs:
  - job_name: sni-router
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/sni-router.token
    static_configs:
      - targets: ["127.0.0.1:9000"]
```

Use the actual API address and write the token into the credentials file with
permissions limited to the Prometheus account. For HTTPS, add `scheme: https`
and the CA settings your deployment requires.

| Metric | Meaning |
|---|---|
| `sni_router_uptime_seconds` | Time since process startup |
| `sni_router_connections_total`, `sni_router_connections_active` | Routed TCP totals and active connection gauge |
| `sni_router_connection_errors_total` | Errors recorded by connection handlers |
| `sni_router_bytes_up_total`, `sni_router_bytes_down_total` | Forwarded bytes recorded by the data paths |
| `sni_router_rate_limited_total` | TCP connections rejected by the per-IP cap |
| `sni_router_udp_flows_total`, `sni_router_udp_datagrams_total` | Routed UDP flows and client datagrams received |
| `sni_router_h2_pool_hits_total` | Backend keep-alive pool reuse; also incremented by HTTP/1.1 termination |
| `sni_router_backend_connections_total`, `sni_router_backend_connections_active` | Per-backend counters/gauges with a `backend` label |
| `sni_router_backend_errors_total` | Errors attributed to a backend |
| `sni_router_backend_bytes_total` | Bytes with `backend` and `dir="up"` / `dir="down"` labels |

These are implementation counters, not a complete traffic accounting system.
In particular, HTTP termination does not populate the byte counters for HTTP
bodies; the active connection gauge is not an HTTP/2 stream count or UDP flow
count. There are no request-rate or latency histogram metrics. Counter series
survive hot reload, including series for removed backend names; a re-exec or
service restart resets them.

`/healthz` only reports that the API handler answered. It does not test traffic
listeners, backend reachability, or successful TLS configuration for every
backend. Monitor a real request through each critical routing path as well.

## Troubleshooting

| Symptom | Check |
|---|---|
| `GLIBC_* not found` at startup | Compare the release's libc requirement with the host; build locally for an older distribution |
| Service is active, but a port is absent | Inspect the journal for bind/runtime/TLS setup failures; check `sudo ss -ltnp` and `sudo ss -lunp` |
| API returns `401` | Supply the configured token as `Authorization: Bearer ...`; all reads require it too |
| API TLS stopped working after renewal | Restart the service; the API certificate is not watched |
| `PUT /config` rejects a file fetched from the API | Restore `api.token`, which GET omits; refetch the ETag if the response is `409` |
| TCP connects but the backend rejects traffic | Check selected SNI/route, port, and whether both ends agree on PROXY protocol |
| UDP responses disappear | Check the UDP backend address, PROXY framing, flow expiry and capacity; TCP probes do not establish UDP health |
| Small transfers work but large ones stall | Compare a direct backend request, inspect `ss -tin` for retransmits, and check the host's MTU/congestion settings |
| A connection sits open without traffic | Check whether it is a tunnel; keepalive does not close reachable but idle peers |

For a TLS route on an unprivileged test port:

```bash
openssl s_client -connect 127.0.0.1:8443 -servername app.example.com </dev/null
```

For an HTTPS application route:

```bash
curl --resolve app.example.com:8443:127.0.0.1 https://app.example.com:8443/
```

Keep the SNI/Host name consistent with the route and certificate. For a private
CA, provide its CA certificate rather than disabling verification. Current
protocol and deployment limitations are recorded in
[Architecture](architecture.md#known-limitations).
