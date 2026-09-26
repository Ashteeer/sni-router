# Documentation

Start with [installation](installation.md), then choose an
[example configuration](../config/examples/). The examples are independent:
copy one, replace its addresses and certificate paths, and run
`sni-router -t /path/to/config.yaml` before starting it.

| Guide | Contents |
| --- | --- |
| [Installation](installation.md) | Release binaries, checksums, installer behavior, manual setup and builds |
| [Configuration](configuration.md) | Complete YAML reference, defaults, validation and reload behavior |
| [Routing](routing.md) | SNI matching, modes, pools, ACLs and PROXY protocol |
| [Operations](operations.md) | CLI, systemd, signals, certificates, updates, logs and troubleshooting |
| [API](api.md) | Authentication, endpoints, config writes, version checks and metrics |
| [Architecture](architecture.md) | Data paths, concurrency, state changes and known limitations |

For development, see [Contributing](../CONTRIBUTING.md). Changes in the current
release are listed in the [changelog](../CHANGELOG.md); earlier releases have
their own [release notes](https://github.com/Ashteeer/sni-router/releases).

The reference describes the code in this checkout. To read documentation for
an older installation, select its `vX.Y.Z` tag on GitHub.
