# Example configurations

Each YAML file is a complete configuration for one deployment. Replace its
addresses and names before use. The TLS examples also need readable PEM
certificate/key files at the indicated paths; those files are not included.

| Example | Use case |
| --- | --- |
| [passthrough.yaml](passthrough.yaml) | Share TCP and QUIC ports between services; certificates stay on the backends |
| [https-termination.yaml](https-termination.yaml) | Terminate HTTPS, accept HTTP/1.1 and HTTP/2, forward to an HTTP application |
| [tls-tcp.yaml](tls-tcp.yaml) | Terminate DNS-over-TLS and send plain TCP to a DNS server |
| [dns.yaml](dns.yaml) | Forward ordinary DNS over both TCP and UDP without inspecting query names |
| [http-redirect.yaml](http-redirect.yaml) | Return a local health response and redirect other HTTP paths to HTTPS |
| [api-only.yaml](api-only.yaml) | Run management and metrics without traffic listeners |
| [backend-tls.yaml](backend-tls.yaml) | Terminate HTTPS and re-encrypt to an upstream verified with a private CA |

Validate the chosen file before running it:

```bash
sni-router -t config/examples/passthrough.yaml
```

The check does not bind ports or contact upstreams. For a foreground trial,
choose free ports first, then run with `-c` instead of `-t`. These examples do
not enable PROXY protocol: enable it only when the upstream is configured to
accept it. The token in `api-only.yaml` is a placeholder and must be replaced.

To apply an example to an existing installation, merge the relevant sections
into your configuration. Replacing the whole file also removes any existing
routes, ACLs and API settings. See [operations](../../docs/operations.md) for
backup, validation and reload commands, and the
[configuration reference](../../docs/configuration.md) for every field.
