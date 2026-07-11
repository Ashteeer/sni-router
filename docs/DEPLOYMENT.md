# Deployment guide

> **Status note:** the project is under active development. Current builds
> fully support configuration validation (`sni-router -t`); the routing
> data path is being implemented. This guide describes the intended
> production setup and is kept up to date as features land.

## Requirements

- Linux, x86_64 or aarch64 (the data path targets io_uring, kernel 5.10+)
- systemd (optional — the binary is self-contained)
- root access for installation

## Quick start

Download the installer, read it, run it:

```bash
wget https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
less install.sh        # always inspect scripts before running them as root
sudo bash install.sh
```

What it does:

1. detects the architecture and downloads the latest release binary
   to `/usr/local/bin/sni-router`;
2. creates `/etc/sni-router/sni-router.yaml` from the example config
   (existing config is never overwritten);
3. registers a systemd unit `sni-router.service` — **installed, not started**:
   nothing binds any port until you explicitly start the service.

## Choosing bind addresses safely

If the machine already runs other services, check that the candidate port is
actually free before pointing `bind` at it:

```bash
ss -tlnp | grep ':443'      # TCP listeners on 443
ss -ulnp | grep ':443'      # UDP (QUIC) on 443
```

A safe rollout on a busy server: start on an unused port first
(e.g. `0.0.0.0:8443`), verify routing works, then move to `:443`.
`sni-router -t` never binds anything and is always safe to run next to live
services.

## Configuration

- Default path: `/etc/sni-router/sni-router.yaml`
- Override with the `SNI_ROUTER_CONFIG` environment variable or an explicit
  CLI path
- Reference: [config/sni-router.example.yaml](../config/sni-router.example.yaml)

Validate after every edit — all errors are reported at once, with exact
config paths:

```bash
sni-router -t
sni-router -t --check-backends   # also TCP-probe each backend server
```

Exit code `0` = valid (warnings allowed), non-zero = errors. Use it as a gate
so a broken config never reaches a running instance:

```bash
sni-router -t && sudo systemctl reload sni-router
```

## TLS certificates with Let's Encrypt (terminate mode)

sni-router does not embed an ACME client — it integrates with the mature ones
(certbot / lego / acme.sh), the way HAProxy and nginx do. Point a terminate
backend's `tls.cert` / `tls.key` at the files a tool like certbot manages:

```yaml
backends:
  api:
    mode: terminate
    tls:
      cert: "/etc/letsencrypt/live/api.example.com/fullchain.pem"
      key:  "/etc/letsencrypt/live/api.example.com/privkey.pem"
    servers: ["10.0.1.5:8080"]
```

Issue the certificate once, then let certbot renew on its timer:

```bash
sudo certbot certonly --standalone -d api.example.com
```

sni-router **watches the cert files and hot-swaps them with zero downtime**
when they change — no restart or reload needed after a renewal.

## Running

```bash
sudo systemctl enable --now sni-router
systemctl status sni-router
journalctl -u sni-router -f          # follow logs
```

## Reload without downtime

`systemctl reload` (SIGHUP) re-reads and validates the config. If the new
config is invalid, the old one keeps working, the error goes to the log, and
active connections are not dropped.

## Upgrading

Re-run the installer — it replaces the binary and never touches your config:

```bash
sudo bash install.sh
sudo systemctl restart sni-router
```

## Uninstall

```bash
sudo systemctl disable --now sni-router
sudo rm /usr/local/bin/sni-router /etc/systemd/system/sni-router.service
sudo systemctl daemon-reload
sudo rm -r /etc/sni-router           # optional: removes your config
```

## Building on a remote server (development)

There is no CI; release binaries are built on a remote Linux box over SSH:

```bash
cp .env.example .env      # set SSH_DEST (alias or user@host)
scripts/deploy.sh         # upload committed tree + cargo build --release
scripts/deploy.sh --test  # run cargo test first
```

The script ships `git archive HEAD`, so only committed files reach the
server, and prints only the relevant tail of the build log.
