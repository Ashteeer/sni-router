# sni-router — configuration reference

This document is the **complete, authoritative reference** for the `sni-router`
configuration file. It is written to be consumed by a program (e.g. a model
generating a web UI that produces this config), so it is explicit about every
field, its type, default, applicability, and validation rules.

The config is a single YAML file. It is intentionally **flat and predictable**
— no anchors, no merge keys, no deeply nested matcher/filter objects — so it can
be generated and edited programmatically and by non-DevOps users.

- Format: YAML (UTF‑8).
- Default path: `/etc/sni-router/sni-router.yaml` (override with `-c <path>` or
  the `SNI_ROUTER_CONFIG` env var).
- Validate without running: `sni-router -t [path]` (like `nginx -t`). It reports
  **all** problems at once with `ERROR`/`WARNING` levels. Exit code `0` means
  valid (warnings allowed); non‑zero means at least one error. Unknown keys are
  rejected (typo protection).

---

## 1. Top-level structure

```yaml
listeners:   [ ... ]   # optional        — how clients are accepted
backends:    { ... }   # optional        — how the router talks to servers
default_tls: { ... }   # optional        — shared cert for terminate backends
timeouts:    { ... }   # optional        — global timeouts (seconds)
limits:      { ... }   # optional        — resource limits
log:         { ... }   # optional        — logging
api:         { ... }   # optional        — management + metrics API (one bind, one token)
```

`listeners` and `backends` may be empty (or omitted): an **API-only config** is
valid — it exposes just the management API, and a web UI fills in the routing
later via `PUT /config`. This is exactly what the installer writes. (If both are
empty *and* there's no `api` section, validation fails — the router would have
nothing to do.) Once you add a listener, it needs at least one backend.

`default_tls` is a single `{ cert, key }` object. Any `terminate`/`terminate_tcp`
backend that omits its own `tls` uses it — so many backends can share one
wildcard cert without repeating paths. A backend's own `tls` always wins.

Mental model, and the single most important design rule:

- A **listener** only decides *how a client connection is accepted* (`bind`
  addresses, `proto`) and *which routes apply*.
- A **backend** decides *what to do with the connection* (`mode`), *how to talk
  to the upstream* (`proxy_protocol`, balancing, TLS), and *what synthetic
  responses to give* (`http_rules`).
- **Routes** live on a listener and map an SNI pattern → a backend **name**.
  Backends are defined once and reused by name across listeners.

So the same listener can route different SNI names to a passthrough backend, a
TLS‑terminating backend, and a redirect — without duplicating listeners.

---

## 2. `listeners` (array, required)

Each listener:

| field   | type              | required | default | notes |
|---------|-------------------|----------|---------|-------|
| `name`  | string            | yes      | —       | unique across listeners; label only |
| `bind`  | array of string   | yes      | —       | one or more `IP:port` accept addresses |
| `proto` | `tcp` \| `udp`    | no       | `tcp`   | `udp` = QUIC passthrough |
| `acl`   | object            | no       | none    | see [ACL](#26-acl) |
| `routes`| array of route    | yes      | —       | first match wins; see [routes](#25-routes) |

### 2.1 `bind`

- Each entry is an `IP:port` string. IPv4 (`0.0.0.0:443`) and IPv6
  (`[::]:443`) are both allowed, in the same listener.
- To listen on both IPv4 and IPv6, **list both explicitly**. Do not rely on
  implicit dual‑stack; each IPv6 socket is forced `IPV6_V6ONLY`.
- The same `IP:port` may appear once per protocol. `tcp` and `udp` on the same
  `IP:port` is allowed (independent sockets); the same `(proto, IP:port)` twice
  (even across listeners) is an **error**.
- Changing `bind`/`proto` requires a process restart; a SIGHUP reload rejects
  such a change and keeps the running config.

### 2.5 `routes`

Ordered list; the **first** matching route wins. Each route:

| field     | type   | required | notes |
|-----------|--------|----------|-------|
| `sni`     | string | yes      | match pattern (below) |
| `backend` | string | yes      | must name an entry in `backends` |

SNI match semantics (identical in routing and validation):

- `example.com` — exact, **case‑insensitive** match.
- `*.example.com` — any subdomain depth (`a.example.com`, `x.y.example.com`),
  but **not** the apex `example.com`.
- `*` — catch‑all; also matches connections with **no SNI** (non‑TLS bytes, or a
  ClientHello without SNI).

Notes for a UI:

- A connection whose SNI matches no route (and no `*`) is dropped.
- If a broad pattern precedes a more specific one (e.g. `*` before
  `api.example.com` in the same listener), the specific route is unreachable —
  validation emits a **WARNING** ("unreachable — shadowed by earlier route").
  Order specific → general.

### 2.6 `acl`

Optional per‑listener access control. Deny always wins; an empty allow list
means "allow all" for that dimension.

| field       | type            | default | notes |
|-------------|-----------------|---------|-------|
| `allow_ip`  | array of string | `[]`    | client IPs/CIDRs permitted (empty = any) |
| `deny_ip`   | array of string | `[]`    | client IPs/CIDRs rejected |
| `allow_sni` | array of string | `[]`    | SNI patterns permitted (same wildcard rules) |
| `deny_sni`  | array of string | `[]`    | SNI patterns rejected |

CIDR entries accept IPv4 and IPv6 (`10.0.0.0/8`, `192.168.1.5`, `2001:db8::/32`).
Invalid CIDRs are an **error**.

---

## 3. `backends` (map, required)

A map of `name → backend`. The `name` (map key) is what routes reference.

Common fields (apply depending on `mode` — see the [applicability
matrix](#38-field-applicability-by-mode)):

| field            | type                                            | default        | notes |
|------------------|-------------------------------------------------|----------------|-------|
| `mode`           | `passthrough`\|`terminate`\|`terminate_tcp`\|`redirect_https` | `passthrough` | what the backend does |
| `proxy_protocol` | `none` \| `v1` \| `v2`                          | `none`         | send the real client IP to the upstream |
| `balance`        | `round_robin` \| `least_conn`                   | `round_robin`  | server selection policy |
| `health_check`   | bool                                            | `false`        | TCP‑connect probe; skip down servers |
| `tls`            | object                                          | none           | cert/key the router presents (terminate modes) |
| `backend_tls`    | object                                          | none           | re‑encrypt/mTLS to the upstream (terminate only) |
| `headers`        | object                                          | all false      | inject `X-Forwarded-*` (terminate only) |
| `http2`          | bool                                            | `false`        | advertise & terminate `h2` (terminate only) |
| `http_rules`     | array of rule                                   | `[]`           | per‑path forward/respond/redirect |
| `servers`        | array of string                                 | `[]`           | upstream `IP:port` addresses |

### 3.1 `mode`

- **`passthrough`** — after reading the SNI, forward the raw TCP (or UDP/QUIC)
  bytes to a server, zero‑copy. No TLS termination. Requires `servers`.
  The only mode valid for `proto: udp`.
- **`terminate`** — terminate the client's TLS, speak HTTP/1.1 (and HTTP/2 if
  `http2: true`) to the client, and forward to `servers` as HTTP/1.1. Supports
  header injection, `backend_tls` re‑encrypt/mTLS, and `http_rules`. Requires
  `tls` and `servers`. TCP only.
- **`terminate_tcp`** — terminate the client's TLS, then forward the decrypted
  stream to `servers` as **raw TCP** (not HTTP). For DoT (`:853`) and other
  non‑HTTP protocols behind TLS. Requires `tls` and `servers`. TCP only. ALPN is
  left unset so the client can negotiate e.g. `dot`.
- **`redirect_https`** — a plaintext‑HTTP responder (typically on `:80`). With no
  `http_rules`, it 301‑redirects every request to the `https://` equivalent
  (host + path preserved). With `http_rules`, it applies them (see below). No
  `servers`, no `tls`. TCP only.

### 3.2 `servers`

- Array of `IP:port` strings (`10.0.0.1:443`, `127.0.0.1:8443`, `[2001:db8::1]:443`).
- **Hostnames are not supported** — IP:port only (a validation error explains
  this).
- Address family is independent from the listener's: an IPv6 client can be
  routed to an IPv4 backend in passthrough.
- Required (≥ 1) for every mode **except** `redirect_https` (which has no
  upstream).

### 3.3 `proxy_protocol`

Sends the real client address to the upstream (the only way to pass it in
passthrough, where there are no HTTP headers). `none` | `v1` (text) | `v2`
(binary). For UDP, the header is sent as its own leading datagram. Not relevant
to `redirect_https`.

### 3.4 `balance` and `health_check`

- `round_robin` (default) or `least_conn` (fewest active connections, counted
  with shared atomics across cores).
- `health_check: true` runs a periodic TCP‑connect probe (interval =
  `timeouts.health_interval`); unhealthy servers are skipped, and connects
  always retry the next server in the pool. Health probing is meaningful for TCP
  backends only.

### 3.5 `tls` (terminate / terminate_tcp)

The certificate the router presents to clients for names routed here. Optional
per backend: if omitted, the top-level `default_tls` is used instead (at least
one of the two must supply a cert for a terminate backend).

| field  | type   | required | notes |
|--------|--------|----------|-------|
| `cert` | string | if no `default_tls` | path to PEM cert chain |
| `key`  | string | if no `default_tls` | path to PEM private key |

Files must exist and be readable at validation time. Certs are **hot‑reloaded**:
if the files change on disk (certbot/lego renewal), they are picked up with zero
downtime — no restart or reload needed.

### 3.6 `backend_tls` (terminate only — re‑encrypt / mTLS)

When present, the router re‑encrypts to the upstream over TLS instead of
plaintext.

| field                  | type   | default | notes |
|------------------------|--------|---------|-------|
| `sni`                  | string | client SNI | ServerName sent to (and verified against) the backend |
| `insecure_skip_verify` | bool   | `false` | skip backend cert verification (test/self‑signed only) |
| `ca`                   | string | system roots | PEM CA to trust for the backend cert |
| `client_cert`          | string | none    | mTLS: client cert presented to the backend |
| `client_key`           | string | none    | mTLS: client key (must be set together with `client_cert`) |

Constraint: **not combinable with `http2: true`** (the h2 gateway forwards to the
backend over HTTP/1.1 plaintext) — this pairing is a validation error.

### 3.7 `headers` (terminate only)

Inject forwarding headers into the HTTP/1.1 (and h2‑gatewayed) request. Each is a
bool, default `false`. Client‑supplied copies of these headers are dropped and
replaced so they cannot be spoofed.

| field               | injected header      | value |
|---------------------|----------------------|-------|
| `x_real_ip`         | `X-Real-IP`          | client IP |
| `x_forwarded_for`   | `X-Forwarded-For`    | appends client IP to any existing chain |
| `x_forwarded_proto` | `X-Forwarded-Proto`  | `https` |

### 3.8 Field applicability by mode

`Y` = used, `—` = ignored (a WARNING is emitted if set), `req` = required.

| field            | passthrough | terminate | terminate_tcp | redirect_https |
|------------------|:-----------:|:---------:|:-------------:|:--------------:|
| `servers`        | req         | req       | req           | — (must be empty/absent) |
| `proxy_protocol` | Y           | —         | Y             | —              |
| `balance`        | Y           | Y         | Y             | —              |
| `health_check`   | Y           | Y         | Y             | —              |
| `tls`            | —           | req       | req           | —              |
| `backend_tls`    | —           | Y         | —             | —              |
| `headers`        | —           | Y         | —             | —              |
| `http2`          | —           | Y         | —             | —              |
| `http_rules`     | —           | Y         | —             | Y              |
| valid for `proto`| tcp + udp   | tcp       | tcp           | tcp            |

---

## 4. `http_rules` — synthetic responses & path routing

`http_rules` is the **single, port‑independent mechanism** for per‑path
behavior. The exact same rules work on a `terminate` backend (over TLS, incl.
HTTP/2) and on a `redirect_https` backend (plaintext). So a 301 redirect or a 404
response can be placed wherever it is needed.

Rules are an ordered list; the **first** rule whose `path` matches wins. If no
rule matches:
- on `terminate`: the request is forwarded to `servers` (default = forward all);
- on `redirect_https`: the response is `404` (unless there are no rules at all,
  in which case the default is a 301 to https).

Each rule:

| field          | type   | required            | applies to | notes |
|----------------|--------|---------------------|------------|-------|
| `path`         | string | yes                 | all        | prefix match, or `*` for catch‑all |
| `action`       | `forward` \| `respond` \| `redirect` | yes | all | |
| `status`       | integer| `respond`: **yes**; `redirect`: optional | respond/redirect | respond: 100–599; redirect: 3xx (default 301) |
| `body`         | string | no                  | respond    | response body (default empty) |
| `content_type` | string | no                  | respond    | default `text/plain` |
| `to`           | string | `redirect`: **yes** | redirect   | `https` or an absolute URL |

`path` matching: prefix. `path: "/dns-query"` matches `/dns-query` and
`/dns-query/anything`. `path: "*"` matches everything.

Actions:

- **`forward`** — send the request to this backend's `servers`. Only meaningful
  on `terminate` (a `forward` rule on `redirect_https` has no upstream → WARNING;
  such requests get 404).
- **`respond`** — answer directly with `status` (+ optional `body`,
  `content_type`). Example: `/blocked` → 404.
- **`redirect`** — answer with a `3xx` and a `Location` header:
  - `to: "https"` → `Location: https://<Host><path>` (the http→https upgrade,
    computed per request).
  - `to: "https://example.com/new"` → literal absolute URL.
  - `status` defaults to `301`; `302`/`307`/`308` etc. are allowed.

Examples:

```yaml
# Envoy-style DoH on a terminate backend: forward /dns-query, 404 the rest.
http_rules:
  - { path: "/dns-query", action: forward }
  - { path: "*",          action: respond, status: 404, body: "not found\n" }
```

```yaml
# Plaintext :80: serve /health, redirect everything else to https.
http_rules:
  - { path: "/health", action: respond,  status: 200, body: "ok\n" }
  - { path: "*",       action: redirect, to: "https" }
```

---

## 5. `timeouts` (object, optional) — seconds

| field             | type | default | notes |
|-------------------|------|---------|-------|
| `handshake`       | int  | `5`     | max time to read the full ClientHello (slowloris protection) |
| `connect`         | int  | `10`    | backend connect timeout |
| `idle`            | int  | `300`   | idle timeout (UDP flows; TLS data phase) |
| `health_interval` | int  | `10`    | how often health‑check probes run |
| `drain`           | int  | `30`    | on SIGTERM, how long to wait for active connections before exit |

All must be `> 0` (error otherwise). Values `> 86400` (24h) produce a WARNING.

---

## 6. `limits` (object, optional)

| field              | type | default | notes |
|--------------------|------|---------|-------|
| `max_client_hello` | int  | `16384` | max bytes buffered while reassembling a ClientHello. Must be ≥ 512 (error) and ≤ 1 MiB (warning above) |
| `max_conns_per_ip` | int  | `0`     | max concurrent TCP connections per client IP (`0` = unlimited) |

---

## 7. `log` (object, optional)

| field    | type            | default | notes |
|----------|-----------------|---------|-------|
| `level`  | `error`\|`warn`\|`info`\|`debug`\|`trace` | `info` | a bare `RUST_LOG=<level>` overrides this |
| `format` | `text` \| `json`| `text`  | `json` = one JSON object per line (for log shippers) |

Access logs are emitted per connection with structured fields (peer, sni,
backend, mode, bytes, duration). Color is used only when stderr is a terminal.

---

## 8. `api` (object, optional)

Unified management + metrics API and control plane (foundation for a web UI).
**One bind, one token** — the same address and token guard config read/write,
reload/restart, and the Prometheus metrics. Runs on one core, off the data path.
This is the only section the installer writes by default; it auto‑generates
`bind` (`0.0.0.0:<random free port>`) and `token`.

| field   | type   | required | notes |
|---------|--------|----------|-------|
| `bind`  | string | yes      | `IP:port`. `0.0.0.0:<port>` to reach it from a remote web UI; protect it with a `token` (and ideally `tls`). |
| `token` | string | no       | if set, **every** request (reads *and* writes) must send `Authorization: Bearer <token>`; never echoed by `/config`. **Required for the write endpoints.** |
| `tls`   | object | no       | `{ cert, key }` to serve the API over HTTPS. If omitted, `default_tls` is used; if neither is set, the API is plaintext HTTP. A cert change is applied on the next restart (not hot‑reloaded). |

### 8.1 Endpoints

Reads (need the token when one is configured — the installer always sets one):

| method + path   | returns | notes |
|-----------------|---------|-------|
| `GET /healthz`  | `ok`    | liveness |
| `GET /status`   | JSON    | version, uptime, listeners, backends |
| `GET /config`   | YAML    | the running config; `api.token` redacted |
| `GET /metrics`  | text    | Prometheus exposition: global counters (connections, bytes, errors, rate‑limited, UDP flows) and per‑backend series |
| `GET /version`  | JSON    | `{"version":"1.4.0"}` — the running binary's version |

Writes (**require `api.token`** — without it they return `403`, so the config
can't be changed unauthenticated):

| method + path   | body        | effect |
|-----------------|-------------|--------|
| `PUT /config`   | YAML config | validate → atomically replace the config file → apply. Invalid config → `400` with a JSON error list, **nothing is written**. The body **must include `api.token`** while one is configured (`GET /config` redacts it, so a blind GET→PUT round‑trip is rejected with `400` instead of silently disabling auth). |
| `POST /reload`  | —           | re‑read the config file from disk and apply it (like SIGHUP). |
| `POST /restart` | —           | validate the on‑disk config, then re‑exec the process (drops connections, rebinds immediately). Privilege‑free equivalent of `systemctl restart`. |
| `POST /update`  | —           | check GitHub for a newer release; if one exists, download it, replace the binary, and re‑exec into it. See below. |

`POST /update` replies synchronously with the decision, then does the work in the
background (a download can outlast the request, and the process re‑execs anyway —
poll `GET /version` to confirm the new version is live):

```json
{"status":"ok","updated":false,"version":"1.4.0"}                       // already latest
{"status":"ok","updated":true,"from":"1.3.0","to":"1.4.0","restarting":true}  // downloading, then restart
```

The update only ever fetches this project's **official** GitHub release assets
(the repo is compiled in, never taken from the request), so it can only install an
official build. It needs write access to the directory the binary lives in — the
installer puts the binary under `/usr/local/lib/sni-router/` owned by the service
user for exactly this reason (with a `/usr/local/bin/sni-router` symlink on PATH).
The same logic backs the CLI: `sni-router -u` (`--update`, add `--force` to
reinstall the latest even if already current) and `sni-router -v` prints the
version.

`PUT /config` and `POST /reload` reply with how the change was applied:

```json
{"status":"ok","applied":"reload","downtime":false}   // hot‑swapped, live conns kept
{"status":"ok","applied":"restart","downtime":true}    // re‑exec was needed
```

**When a restart is needed vs. zero‑downtime hot‑swap** (same rule as SIGHUP): a
change to routes, ACLs, timeouts, limits, or passthrough/redirect backends
(including their server lists) is applied live. A change to a listener's
`bind`/`proto`, a `terminate`/`terminate_tcp` backend's TLS/headers/http2/
http_rules, `default_tls`, or the `api`/`log` sections requires a restart —
`PUT`/`POST` perform it automatically and report `"applied":"restart"`.
(`api.token` alone is hot‑swappable.)

A validation error body:

```json
{"error":"validation failed","errors":[{"path":"backends.web.servers[0]","message":"\"10.0.0.1\" — missing port"}]}
```

> **Writable config file & binary.** `PUT /config` rewrites the config on disk and
> `POST /update` replaces the binary, so the service process must have write
> access to both. The installer creates a static `sni-router` system user that
> owns `/etc/sni-router` (0750, config 0600 — it holds the api token) **and**
> `/usr/local/lib/sni-router/` (where the binary lives, with a
> `/usr/local/bin/sni-router` symlink on PATH), and runs the service as that user.
> (`DynamicUser` doesn't work here: systemd does not chown an existing directory
> to the dynamic user.) Under snap the config lives in `$SNAP_DATA` (already
> writable by the root daemon).

---

## 10. Validation rules (what `-t` checks)

Errors (exit non‑zero):

1. YAML syntax (with line/column).
2. Unknown keys / wrong types (typo protection via `deny_unknown_fields`).
3. `bind` and `servers` are valid `IP:port` (IPv4 octet ranges, `[...]` IPv6).
4. Duplicate `(proto, IP:port)` binds.
5. Every `route.backend` names an existing backend (with a "did you mean …?"
   suggestion on a near miss).
6. `terminate`/`terminate_tcp` have a cert with readable `cert`/`key` — either
   the backend's own `tls` or the top-level `default_tls`.
7. `backend_tls` files readable; mTLS needs both `client_cert` and `client_key`.
8. `http2: true` not combined with `backend_tls`.
9. `http_rules`: `path` non‑empty; `respond` has a valid `status` (100–599);
   `redirect` has `to` (`https` or an absolute URL) and a 3xx `status` if set.
10. `servers` non‑empty for every mode except `redirect_https`.
11. `udp` listeners route only to `passthrough` backends.
12. Timeouts `> 0`; `max_client_hello ≥ 512`; valid `log.level`; valid
    `api.bind`.

Warnings (still exit `0`):

- Unreachable (shadowed) routes.
- Fields set but ignored for the chosen mode (see the applicability matrix).
- A backend not referenced by any route.
- Unusually large timeouts / buffer sizes.

Optional network check: `sni-router -t --check-backends` additionally does a real
TCP connect to each server (opt‑in side effect).

---

## 11. Reload & shutdown behavior (for a UI to surface)

- **SIGHUP**: re‑reads and validates the file. On any error the old config keeps
  serving. Applies changes to routes/backends/timeouts/ACLs for **new**
  connections; live connections keep the config they started with (zero
  downtime). If `bind`/`proto` changed, it instead **fast-restarts** in place
  (re-exec, same PID) to apply the new listeners — active connections drop.
- **SIGUSR1**: fast restart on demand — validate the config, then re-exec in
  place, dropping all connections and rebinding immediately (no drain). Use this
  as the quick "restart now" instead of stop+start.
- **SIGTERM/SIGINT**: graceful shutdown — stop accepting new connections, wait up
  to `timeouts.drain` seconds for active ones to finish, then exit.
- **API**: `PUT /config` / `POST /reload` apply changes the same way as SIGHUP
  (hot‑swap or restart, reported in the response); `POST /restart` forces a
  re‑exec. See [§8.1](#81-endpoints).

---

## 12. Worked examples

### 12.1 Minimal passthrough

```yaml
listeners:
  - name: tls
    bind: ["0.0.0.0:443", "[::]:443"]
    proto: tcp
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    servers: ["10.0.0.1:443"]
```

### 12.2 Passthrough + PROXY protocol + health checks + least_conn

```yaml
backends:
  web:
    mode: passthrough
    proxy_protocol: v2
    balance: least_conn
    health_check: true
    servers: ["10.0.0.1:443", "10.0.0.2:443"]
```

### 12.3 TLS terminate with header injection and h2

```yaml
listeners:
  - name: https
    bind: ["0.0.0.0:443"]
    proto: tcp
    routes:
      - { sni: "app.example.com", backend: app }
backends:
  app:
    mode: terminate
    http2: true
    tls: { cert: "/etc/sni-router/certs/app.pem", key: "/etc/sni-router/certs/app.key" }
    headers: { x_real_ip: true, x_forwarded_for: true, x_forwarded_proto: true }
    servers: ["10.0.1.5:8080"]
```

### 12.4 :80 → :443 redirect (one‑liner), plus a health exception

```yaml
listeners:
  - name: http
    bind: ["0.0.0.0:80", "[::]:80"]
    proto: tcp
    routes:
      - { sni: "*", backend: to_https }
backends:
  to_https:
    mode: redirect_https
    http_rules:                       # optional; omit for "redirect everything"
      - { path: "/health", action: respond,  status: 200, body: "ok\n" }
      - { path: "*",       action: redirect, to: "https" }
```

### 12.5 DNS‑over‑TLS (raw TCP terminate) on :853

```yaml
listeners:
  - name: dot
    bind: ["0.0.0.0:853"]
    proto: tcp
    routes:
      - { sni: "*", backend: dns }
backends:
  dns:
    mode: terminate_tcp
    tls: { cert: "/etc/sni-router/certs/dns.pem", key: "/etc/sni-router/certs/dns.key" }
    servers: ["10.0.2.5:53"]
```

### 12.6 QUIC passthrough on udp/443

```yaml
listeners:
  - name: quic
    bind: ["0.0.0.0:443", "[::]:443"]
    proto: udp
    routes:
      - { sni: "*", backend: web }
backends:
  web:
    mode: passthrough      # the only mode valid for udp
    servers: ["10.0.0.1:443"]
```

---

## 13. Quick JSON‑shape summary (for form generation)

```
Config {
  listeners?: Listener[]                      // may be empty (API-only config)
  backends?: { [name: string]: Backend }      // may be empty (API-only config)
  default_tls?: { cert: string, key: string } // shared cert for terminate backends
  timeouts?: { handshake, connect, idle, health_interval, drain }   // ints, seconds
  limits?: { max_client_hello, max_conns_per_ip }                   // ints
  log?: { level: enum, format: enum }
  api?: { bind: string, token?: string, tls?: { cert: string, key: string } }
}

Listener {
  name: string
  bind: string[]                              // IP:port
  proto?: "tcp" | "udp"                       // default tcp
  acl?: { allow_ip[], deny_ip[], allow_sni[], deny_sni[] }
  routes: { sni: string, backend: string }[]  // ordered, first match wins
}

Backend {
  mode?: "passthrough" | "terminate" | "terminate_tcp" | "redirect_https"
  proxy_protocol?: "none" | "v1" | "v2"
  balance?: "round_robin" | "least_conn"
  health_check?: bool
  tls?: { cert: string, key: string }
  backend_tls?: { sni?, insecure_skip_verify?, ca?, client_cert?, client_key? }
  headers?: { x_real_ip?, x_forwarded_for?, x_forwarded_proto? }
  http2?: bool
  http_rules?: HttpRule[]
  servers?: string[]                          // IP:port; required unless redirect_https
}

HttpRule {
  path: string                                // prefix, or "*"
  action: "forward" | "respond" | "redirect"
  status?: int                                // respond: required (100-599); redirect: 3xx (default 301)
  body?: string                               // respond
  content_type?: string                       // respond (default text/plain)
  to?: string                                 // redirect: required ("https" | absolute URL)
}
```

See `config/sni-router.example.yaml` for a heavily‑commented example that passes
`sni-router -t`.
