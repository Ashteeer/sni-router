# Changelog

## [1.9.3](https://github.com/Ashteeer/sni-router/releases/tag/v1.9.3)

- Stop an HTTP/2 terminated connection on its first connection-level I/O
  error. Previously, a disconnect while TLS output was queued could make one
  worker repeatedly submit the same send to a closed socket and receive
  `EPIPE`, saturating one CPU core indefinitely.
- Keep the failure scoped to the affected connection; other connections and
  workers continue normally. Add a regression test that makes h2 accept errors
  terminal instead of polling the failed connection again.

## [1.9.2](https://github.com/Ashteeer/sni-router/releases/tag/v1.9.2)

- Keep management available after self-update/restart when io_uring allocation
  fails. Workers retry temporary resource errors for up to two seconds, then
  fall back to epoll instead of silently disappearing. If both drivers fail,
  exit with an error so a service manager can recover the process.
- Prevent TCP passthrough from saturating a CPU when socket readiness keeps
  waking a transfer that still returns `EAGAIN`. Repeated wakeups without
  progress now use a bounded asynchronous backoff of 1–16 ms; successful
  transfers reset it and the normal forwarding path has no added timer.
- Apply the same protection to the userspace copy fallback. Preserve buffered
  bytes, TCP half-close behavior and the existing configuration schema.
- Add an isolated Linux regression test that injects false write readiness,
  checks bounded retries and verifies data in both directions.
- Test startup and three API re-execs with a child-only locked-memory limit,
  verifying that the API and every configured worker remain available. Skip
  the bulk TCP unit test on WSL1, whose readiness handling can stall the baseline.

## [1.9.1](https://github.com/Ashteeer/sni-router/releases/tag/v1.9.1)

This release reorganizes the project documentation. Routing behavior and the
configuration schema are unchanged.

- Replaced the README with a project overview, a small routing example and
  direct links to task-specific guides.
- Added installation, configuration, routing, operations, API and architecture
  guides, including current limitations and the exact reload behavior.
- Added seven standalone configurations covering TCP/QUIC passthrough, HTTPS,
  raw TLS, DNS, redirects, API-only management and upstream TLS.
- Corrected installation instructions: a fresh install starts an API-only
  service, the executable lives in a service-owned directory, and updates
  preserve the configuration but replace the systemd unit.
- Kept `config.md` and `docs/DEPLOYMENT.md` as entry points to the new guides,
  and added contribution instructions.

Earlier changes are recorded in the
[GitHub release notes](https://github.com/Ashteeer/sni-router/releases).
