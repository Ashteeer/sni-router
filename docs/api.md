# Management API

The API provides configuration management, process control, version reporting,
and Prometheus metrics on one listener. It is optional and configured under
`api`; there are no separate `admin` or `metrics` listeners.

```yaml
api:
  bind: "127.0.0.1:9000"
  token: "replace-with-a-random-secret"
```

For HTTPS, set `api.tls: {cert, key}`. If omitted, the API inherits
`default_tls`; if neither exists, it serves HTTP. A configured TLS context that
cannot be loaded disables the API listener rather than falling back to HTTP.
The API certificate is loaded at startup and is not hot-reloaded.

## Authentication and transport

When `api.token` is configured, every endpoint, including `/healthz`, `/version`,
and `/metrics`, requires:

```http
Authorization: Bearer <token>
```

Header names are case-insensitive; use the case-sensitive `Bearer ` prefix
shown above. With no configured token, reads are public and writes return
`403`. A missing or incorrect token on an authenticated API returns `401`.
The token has full management access; there are no separate read-only tokens
or per-endpoint roles.

Use HTTPS or a trusted local/private connection. The standard installer opens
the API on all IPv4 interfaces using HTTP unless certificate flags are supplied;
see [installation](installation.md).

The API handles HTTP/1.1 requests and closes the connection after each
response. Send exact endpoint paths: query strings and trailing slashes are
not normalized. There is no CORS/preflight support. A browser-based management
application needs a same-origin server or proxy for API access.

Each API connection has a fixed ten-second deadline covering TLS, the request,
and the response. A slow or stalled request can be closed without an error
body. The request-head buffer has a 16 KiB size guard; configuration bodies
are limited to 1 MiB.

Examples use shell variables:

```bash
API_URL=http://127.0.0.1:9000
read -rsp 'API token: ' API_TOKEN; printf '\n'
curl --fail-with-body -H "Authorization: Bearer $API_TOKEN" "$API_URL/status"
```

Replace the URL with the actual configured endpoint. Using `read` avoids
putting the token itself into shell history.

## Endpoints

| Method | Path | Response | Effect |
|---|---|---|---|
| GET | `/healthz` | Plain text | API liveness |
| GET | `/status` | JSON | Running configuration summary |
| GET | `/config` | YAML + `ETag` | Effective configuration with token omitted |
| GET | `/metrics` | Prometheus text | Current counters and gauges |
| GET | `/version` | JSON | Running binary version |
| PUT | `/config` | JSON | Replace the complete file and apply it |
| POST | `/reload` | JSON | Read and apply the existing file |
| POST | `/restart` | JSON | Validate the file and restart immediately |
| POST | `/update` | JSON | Check for an official update, then install and restart |

Successful requests return `200`. Responses include `Content-Type`,
`Content-Length`, and `Connection: close`.

## GET /healthz

```text
ok
```

This is API liveness, not backend or data-path readiness. A running API can
answer even when a traffic listener failed to bind or a backend is unavailable.

## GET /status

```json
{
  "version": "1.9.1",
  "uptime_secs": 120,
  "listeners": [
    {"name": "tls", "proto": "tcp", "bind": ["0.0.0.0:443"]}
  ],
  "backends": [
    {"name": "web", "mode": "passthrough", "servers": 2}
  ]
}
```

`version` is the compiled binary version. `uptime_secs` resets on restart,
including re-exec at the same PID. `servers` is the configured address count,
not a healthy-server count. The listener list describes configuration; it
does not report per-socket bind success. An API-only instance has empty
listener and backend arrays.

## GET /config

Returns the in-memory configuration as `application/yaml`, with defaults
expanded by serialization. It is not the original file: comments, formatting,
and the `api.token` field are omitted. It does not expose pending edits made
to the file that have not been reloaded.

The response includes an opaque quoted ETag, for example:

```http
ETag: "0123456789abcdef"
```

Save the value exactly, including quotes, for a later `If-Match` header.
The tag represents the serialized, token-redacted configuration. Token-only
changes do not change it, and it is not a cryptographic integrity check.

```bash
umask 077
curl --fail-with-body \
  -H "Authorization: Bearer $API_TOKEN" \
  -D config.headers -o config.yaml "$API_URL/config"
```

Do not PUT this response back unchanged: restore the token first.

## PUT /config

The body must contain the **entire replacement configuration** as UTF-8 YAML,
not a patch. There is no JSON representation negotiated through `Accept` or
`Content-Type`. Send `Content-Length`; chunked request bodies are not supported.
`curl --data-binary @file` supplies the length for an ordinary file.

The server parses and statically validates the body using the same validator
as `sni-router -t`. Invalid input returns `400` without changing the file.
Validation warnings do not reject the request and are not included in the
success response.

If the current API has a token and the replacement keeps `api` but omits its
token, the request returns `400`. Include the existing token or a replacement
token in the YAML. To deliberately remove authentication while retaining the
API, edit the file on disk and reload. Removing the entire `api` section is
allowed if the remaining configuration is valid; this disables the API after
restart.

Use `If-Match` to avoid overwriting another editor's configuration changes:

```bash
ETAG=$(awk 'tolower($1) == "etag:" {gsub(/\r/, "", $2); print $2}' config.headers)

# Edit config.yaml and restore api.token before sending it.
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $API_TOKEN" \
  -H 'Content-Type: application/yaml' \
  -H "If-Match: $ETAG" \
  --data-binary @config.yaml "$API_URL/config"
```

An ETag mismatch returns `409`. Fetch the latest configuration, reconcile your
edits, and retry with its ETag. Omitting `If-Match` or sending `If-Match: *`
makes the write unconditional. The ETag compares the running configuration,
not unreloaded edits on disk, and does not detect token-only changes.

After validation and the ETag check, the server writes a temporary file beside
the configured file and renames it over the target. The target's existing mode
is preserved, or `0600` is used for a new file. The service account needs write
access to the containing directory. Submitted comments and formatting are
preserved in the file because the original request bytes are written.

For a hot reload:

```json
{"status":"ok","applied":"reload","downtime":false}
```

For a change requiring re-exec:

```json
{"status":"ok","applied":"restart","downtime":true}
```

In the restart case, the server sends the response and then immediately
re-execs. Active connections are dropped. The response describes the selected
action; it does not confirm that the new process successfully bound every
listener. The file has already been replaced, and there is no automatic
rollback if subsequent startup fails. Reconnect to confirm status and test
the affected traffic path.

See [reload behavior](operations.md#reload-and-restart) for the fields that
trigger a restart. A token-only change applies live; use the new token for
subsequent requests.

## POST /reload

Reads the process's configured file, validates it, and applies it using the
same rules as `SIGHUP`. No request body is needed. It returns the same
`applied` and `downtime` fields as `PUT /config`.

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $API_TOKEN" "$API_URL/reload"
```

A load or validation failure returns `400` and leaves the running
configuration intact. This endpoint does not rewrite the file and does not
use `If-Match`.

## POST /restart

Validates the file on disk, replies, and re-execs the binary at the same PID
without waiting for a graceful drain:

```json
{"status":"ok","applied":"restart","downtime":true}
```

A load or validation failure returns `400` and cancels the restart. Existing
connections are dropped on a successful restart. This is also the way to
reload API certificates when the configured paths have not changed.

## POST /update

Checks the latest release from the fixed `Ashteeer/sni-router` repository. The
request cannot choose another repository, URL, or version, and has no force
option. If no newer version is available:

```json
{"status":"ok","updated":false,"version":"1.9.1"}
```

If a newer release is available, the response has this shape:

```json
{"status":"ok","updated":true,"from":"1.9.0","to":"1.9.1","restarting":true}
```

`updated:true` means the update was **scheduled**, not completed. The version
check finishes before the response; downloading, checksum verification, binary
replacement, and re-exec happen afterward on a background thread. The request
can therefore finish while the old version is still running.

Poll `GET /version` until it reports `to`, allowing for a connection interruption
during restart. On download or verification failure, the running version stays
unchanged and the failure is written to the journal. There is no update-job
status endpoint, cancellation endpoint, or progress stream. Avoid submitting
another update while one is in progress.

The updater needs `curl` or `wget`, `tar`, outbound HTTPS access, a matching
release asset and `SHA256SUMS` entry, and write permission in the executable's
directory. Missing or mismatched checksums abort replacement. A failed version
check returns `502`; a check that outlasts the connection deadline can instead
end with a closed connection.

## GET /version

```json
{"version":"1.9.1"}
```

Reports the version compiled into the running process, not the latest release
or a replacement binary waiting on disk.

## GET /metrics

Returns `text/plain; version=0.0.4; charset=utf-8`. See
[Metrics](operations.md#metrics) for the exposed series, accounting limits,
and a Prometheus scrape example.

## Error responses

| Status | Meaning |
|---|---|
| `400` | Invalid UTF-8/YAML/configuration, incomplete body, or missing replacement token |
| `401` | Missing or incorrect bearer token; plain-text body |
| `403` | A write was attempted without a configured `api.token` |
| `404` | Unknown path or unsupported GET/PUT/POST combination |
| `405` | Unsupported method, such as DELETE, PATCH, HEAD or OPTIONS |
| `409` | `If-Match` does not equal the current ETag |
| `411` | `PUT /config` has no valid `Content-Length` |
| `413` | Configuration body exceeds 1 MiB |
| `431` | Request-head buffer guard was exceeded |
| `500` | Configuration file could not be written |
| `502` | Update version check failed |

Authentication is checked before endpoint dispatch, so an unauthenticated
request can receive `401` or `403` before an endpoint/method error.

Most write errors use a JSON `error` string. Static validation errors also
contain an array of configuration paths and messages:

```json
{
  "error": "validation failed",
  "errors": [
    {"path": "listeners[0].routes[0].backend", "message": "..."}
  ]
}
```

Not every failure is JSON: authentication, missing routes, unsupported
methods, and header-size responses use plain text. A deadline, TLS failure,
or disconnected client may produce no HTTP response.
