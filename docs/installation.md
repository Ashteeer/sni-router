# Installation

sni-router runs on Linux. The release archive contains the executable; the
installer adds a service account, configuration directory, and systemd unit.
There is no bundled web interface.

## Requirements

Use a Linux host with io_uring available to the service. Container security
profiles and host policy can disable io_uring even on a recent kernel. The
runtime can fall back to epoll, but that is not the intended performance path.

For the installer, you need root, systemd, Bash, `tar`, `curl` or `wget`, and the
usual Linux administration tools, including `ss` and `useradd`. `openssl` is
optional: the installer falls back to `/dev/urandom` for token generation.

The current [release](https://github.com/Ashteeer/sni-router/releases/latest)
provides an x86_64 archive. The installer recognizes x86_64 and aarch64, but an
aarch64 build must currently be [built from source](../CONTRIBUTING.md).
Check individual releases before selecting a different architecture. Prebuilt binaries are
dynamically linked; their libc requirements are listed in the release notes.

## Install with systemd

Download and inspect the script before running it:

```bash
wget https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
less install.sh
sudo bash install.sh
```

On a new installation, the script creates a minimal **API-only configuration**
and immediately enables and starts `sni-router.service`. It does not create
traffic listeners on ports 80 or 443. It binds the management API to
`0.0.0.0` on a randomly selected free TCP port in 20000–39999, with 9000 as a
fallback, and prints the URL and generated bearer token.

The default API transport is HTTP. Before using it across an untrusted network,
restrict access with a firewall or provide TLS. A random port and bearer token
do not encrypt requests. The installer does not configure the firewall.

To use an existing certificate on a fresh installation:

```bash
sudo bash install.sh \
  --cert /etc/letsencrypt/live/router.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/router.example.com/privkey.pem
```

Both flags are required together. They populate `default_tls`, which the API
inherits. Use a hostname covered by the certificate when connecting; the IP
address printed by the installer may not be covered. These flags do not modify
an existing configuration during a normal update.

Check the running service:

```bash
systemctl status sni-router
sudo journalctl -u sni-router -n 50 --no-pager
sni-router --version
```

Add listeners and backends using the [configuration guide](configuration.md),
either by editing `/etc/sni-router/sni-router.yaml` or through
[`PUT /config`](api.md#put-config). Preserve the generated `api` section if
you want to keep management access.

```bash
sudo cp -a /etc/sni-router/sni-router.yaml /etc/sni-router/sni-router.yaml.bak
sudoedit /etc/sni-router/sni-router.yaml
sudo sni-router -t
sudo systemctl reload sni-router
```

Run the reload only after validation succeeds. Adding a listener causes a
restart; see [reload behavior](operations.md#reload-and-restart).

## Installed files and permissions

| Path | Purpose |
|---|---|
| `/usr/local/lib/sni-router/sni-router` | Real executable, mode `0755` |
| `/usr/local/bin/sni-router` | Symlink to the executable |
| `/etc/sni-router/sni-router.yaml` | Configuration, mode `0600` |
| `/etc/sni-router/` | Configuration directory, mode `0750` |
| `/etc/systemd/system/sni-router.service` | Installer-managed unit |

The static `sni-router` user and group own the binary directory and configuration
directory. Write access to the binary directory allows the service to install
updates by atomic replacement. Write access to the configuration directory
allows `PUT /config` to replace the file.

The service runs as this account with two Linux capabilities:

| Capability | Reason |
|---|---|
| `CAP_NET_BIND_SERVICE` | Bind ports below 1024 without running as root |
| `CAP_DAC_READ_SEARCH` | Read certificates and keys in root-owned directories, including after renewal |

`CAP_DAC_READ_SEARCH` grants broad read access, not just access to the configured
certificate paths. Keep the management token private: it authorizes configuration
changes, restarts, and installation of official releases. The unit sets
`NoNewPrivileges=true`, `Restart=on-failure`, and `LimitNOFILE=1048576`.

The installer rewrites the unit on every run. Put local customizations in a
drop-in created with:

```bash
sudo systemctl edit sni-router
```

For example, use an alternative configuration path:

```ini
[Service]
Environment=SNI_ROUTER_CONFIG=/etc/sni-router/edge.yaml
```

Restart the service to apply a unit change. Keep an alternative configuration
inside a directory writable by the service if you need `PUT /config`.

## Updates and rollback

Re-running the installer downloads the latest release, preserves the existing
configuration, refreshes the unit, and restarts the service if it is running:

```bash
sudo bash install.sh
```

A stopped service is normally left stopped. If the configuration is missing,
the script generates a new API-only configuration and starts the service.
The installer also reapplies ownership to the binary and configuration
directories and resets the main configuration file to mode `0600`.

To select a release, including an older one for rollback:

```bash
sudo bash install.sh --version 1.9.0
```

Replace the version with the release you want. Validate configuration
compatibility before rolling back: older binaries may reject newer fields.
Retain a matching configuration backup alongside a binary backup.

`--reinstall` regenerates the configuration and token. It overwrites local
configuration without making a backup, so it is not an update command. On an
already running installation, explicitly restart afterward to load the new
configuration; `systemctl enable --now` does not restart an active service.

The built-in updater is another option:

```bash
sudo sni-router --update
```

It fetches the latest official release, checks its `SHA256SUMS`, atomically
replaces the executable, and attempts `systemctl try-restart sni-router`.
`--force` reinstalls the latest release even if the current version is the same
or newer. It does not select an arbitrary version. The
[API update endpoint](api.md#post-update) can perform an update from the running
service.

The installer currently downloads over HTTPS without checking `SHA256SUMS`.
The built-in updater does check it. To verify a release archive yourself, use
the following procedure.

## Download and verify a release archive

Select a version and architecture from the release page. Work in an empty
directory:

```bash
VERSION=v1.9.1
ARCH=x86_64
ASSET="sni-router-${VERSION}-${ARCH}-linux.tar.gz"
BASE="https://github.com/Ashteeer/sni-router/releases/download/${VERSION}"
WORKDIR="$(mktemp -d)"
cd "$WORKDIR"
curl -fLO "$BASE/$ASSET"
curl -fLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
```

Confirm that the selected archive is reported as `OK` before extracting it:

```bash
tar -xzf "$ASSET"
./sni-router --version
./sni-router -t /path/to/sni-router.yaml
./sni-router -c /path/to/sni-router.yaml
```

This runs the executable directly; it does not install a service. Choose
unprivileged ports or arrange the necessary privileges yourself. A checksum
detects a mismatch with the published manifest; the manifest is not a detached
signature.

## Snap packaging

The repository includes [Snapcraft packaging](../snap/snapcraft.yaml) using
`core24` and classic confinement. Store availability depends on the published
channel and review status; the GitHub release archive and installer are the
documented installation path.

The snap configuration path is `$SNAP_DATA/sni-router.yaml`. Its daemon is
disabled on installation so that a configuration can be supplied before start.
Use snap's package management for snap installations, rather than the built-in
binary updater.

## Remove the systemd installation

Stop and disable the service, then remove its executable and unit:

```bash
sudo systemctl disable --now sni-router
sudo rm /usr/local/bin/sni-router
sudo rm /usr/local/lib/sni-router/sni-router
sudo rmdir /usr/local/lib/sni-router
sudo rm /etc/systemd/system/sni-router.service
sudo systemctl daemon-reload
```

This preserves `/etc/sni-router`, its token, any service drop-ins, and the
service account. Archive the configuration before deleting any of those
separately. `rmdir` deliberately refuses to remove a directory containing
additional files.
