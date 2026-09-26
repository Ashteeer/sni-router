# Changelog

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
