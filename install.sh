#!/usr/bin/env bash
# sni-router installer / updater: downloads a release binary and sets up systemd.
#
# Usage:
#   wget https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
#   less install.sh        # always read scripts before running them as root
#   sudo bash install.sh                 # install, or update in place (keeps config)
#   sudo bash install.sh -v 1.1.0        # install/update a specific version
#   sudo bash install.sh --reinstall     # wipe and reinstall everything (incl. config)
#   sudo bash install.sh --cert /path/fullchain.pem --key /path/privkey.pem
#                                        # on a fresh install, wire these into
#                                        # default_tls and serve the management
#                                        # API over HTTPS
#
# Re-running updates the binary in place without touching the config. Pass
# --reinstall to also overwrite the config and systemd unit from scratch.
#
# A fresh install writes a minimal config that ONLY exposes the management +
# metrics API, generating its bind (0.0.0.0:<random free port>) and access token
# automatically and printing them at the end — so a web UI on another server can
# log in and configure listeners/backends remotely. The service is enabled and
# started; routing is added later through the API (or by editing the config).
set -euo pipefail

REPO="Ashteeer/sni-router"
BIN_DIR="/usr/local/bin"
# The real binary lives in a directory owned by the service user so the service
# can replace it itself (POST /update / `sni-router -u`): an atomic in-place
# update needs write access to the directory the binary sits in. BIN_DIR just
# holds a symlink for CLI convenience.
LIBDIR="/usr/local/lib/sni-router"
CONF_DIR="/etc/sni-router"
UNIT="/etc/systemd/system/sni-router.service"

VERSION=""
REINSTALL=0
CERT=""
KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    -v|--version) VERSION="${2:-}"; [ -n "$VERSION" ] || { echo "error: -v needs a version"; exit 1; }; shift 2 ;;
    --reinstall)  REINSTALL=1; shift ;;
    --cert)       CERT="${2:-}"; [ -n "$CERT" ] || { echo "error: --cert needs a path"; exit 1; }; shift 2 ;;
    --key)        KEY="${2:-}";  [ -n "$KEY" ]  || { echo "error: --key needs a path";  exit 1; }; shift 2 ;;
    -h|--help)    sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "error: unknown argument \"$1\" (see --help)"; exit 1 ;;
  esac
done

# --cert and --key must be given together (or not at all).
if { [ -n "$CERT" ] && [ -z "$KEY" ]; } || { [ -z "$CERT" ] && [ -n "$KEY" ]; }; then
  echo "error: --cert and --key must be provided together"; exit 1
fi

[ "$(uname -s)" = "Linux" ] || { echo "error: sni-router is Linux-only"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "error: run as root: sudo bash install.sh"; exit 1; }

case "$(uname -m)" in
  x86_64)        ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "error: unsupported architecture: $(uname -m)"; exit 1 ;;
esac

dl() { # dl <url> <output-file>
  if command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"; else curl -fsSL -o "$2" "$1"; fi
}

# Pick a random TCP port in 20000-39999 that nothing is currently listening on.
pick_free_port() {
  local p i
  for i in $(seq 1 100); do
    p=$(( (RANDOM % 20000) + 20000 ))
    if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$p\$"; then
      echo "$p"; return 0
    fi
  done
  echo 9000  # fallback: unlikely, but never leave the port empty
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Resolve the tag: explicit -v (normalized to a leading "v"), else the latest release.
if [ -n "$VERSION" ]; then
  case "$VERSION" in v*) TAG="$VERSION" ;; *) TAG="v$VERSION" ;; esac
  echo "==> using requested version $TAG"
else
  echo "==> looking up the latest release of $REPO"
  dl "https://api.github.com/repos/$REPO/releases/latest" "$TMP/release.json" || true
  TAG="$(grep -m1 '"tag_name"' "$TMP/release.json" 2>/dev/null | cut -d'"' -f4 || true)"
  if [ -z "${TAG:-}" ]; then
    echo "error: no published releases yet — build from source instead (see README.md)"
    exit 1
  fi
fi

# Is this an update (binary already present) or a fresh install?
UPDATE=0
{ [ -x "$LIBDIR/sni-router" ] || [ -x "$BIN_DIR/sni-router" ]; } && [ "$REINSTALL" -eq 0 ] && UPDATE=1

# The service user must exist before it can own the binary directory.
if ! id -u sni-router >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --shell /usr/sbin/nologin sni-router
fi

ASSET="sni-router-$TAG-$ARCH-linux.tar.gz"
echo "==> downloading $ASSET"
dl "https://github.com/$REPO/releases/download/$TAG/$ASSET" "$TMP/$ASSET"
tar -xzf "$TMP/$ASSET" -C "$TMP"

# Install the real binary into a service-owned directory, and expose it via a
# symlink on PATH. The service user owns LIBDIR so it can atomically replace the
# binary during a self-update.
mkdir -p "$LIBDIR"
install -m 0755 "$TMP/sni-router" "$LIBDIR/sni-router"
chown -R sni-router:sni-router "$LIBDIR"
chmod 0755 "$LIBDIR"
# Migrate older installs that had a real binary at $BIN_DIR/sni-router.
[ -e "$BIN_DIR/sni-router" ] && [ ! -L "$BIN_DIR/sni-router" ] && rm -f "$BIN_DIR/sni-router"
ln -sfn "$LIBDIR/sni-router" "$BIN_DIR/sni-router"

mkdir -p "$CONF_DIR"
# Config: keep the user's on update; (re)write it only on a fresh install or --reinstall.
FRESH_CONFIG=0
API_TOKEN=""
API_SCHEME="http"
API_HOST="0.0.0.0"          # listen on all interfaces so a remote web UI can reach it
API_PORT=""
if [ ! -f "$CONF_DIR/sni-router.yaml" ] || [ "$REINSTALL" -eq 1 ]; then
  echo "==> generating default config at $CONF_DIR/sni-router.yaml"
  FRESH_CONFIG=1

  # Auto-generate the API access: a random free port and a random token.
  API_PORT="$(pick_free_port)"
  if command -v openssl >/dev/null 2>&1; then
    API_TOKEN="$(openssl rand -hex 24)"
  else
    API_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi

  # A minimal config: nothing but API access. Listeners/backends are added
  # later through the API (PUT /config) or by editing this file. With a cert,
  # default_tls is wired in and the API is served over HTTPS.
  {
    echo "# sni-router — generated by install.sh. Only the management + metrics"
    echo "# API is configured; add listeners/backends via the API or by editing"
    echo "# this file, then reload. Full config reference: config.md in the repo."
    echo "listeners: []"
    echo "backends: {}"
    if [ -n "$CERT" ]; then
      API_SCHEME="https"
      echo "default_tls:"
      echo "  cert: \"$CERT\""
      echo "  key: \"$KEY\""
    fi
    echo "api:"
    echo "  bind: \"$API_HOST:$API_PORT\""
    echo "  token: \"$API_TOKEN\""
  } > "$CONF_DIR/sni-router.yaml"
else
  echo "==> keeping existing config $CONF_DIR/sni-router.yaml"
fi

# The static sni-router system user (created above) owns /etc/sni-router: the
# config holds the api token (must not be world-readable) and `PUT /config`
# rewrites it from inside the service. DynamicUser can't do this — systemd does
# not chown an existing ConfigurationDirectory (or its files) to the dynamic
# user, so the service could neither read a 0600 config nor replace it (verified
# on systemd 255).
chown -R sni-router:sni-router "$CONF_DIR"
chmod 750 "$CONF_DIR"
[ -f "$CONF_DIR/sni-router.yaml" ] && chmod 600 "$CONF_DIR/sni-router.yaml"

# The unit file is installer-owned and kept in sync with the binary on every
# run (v1.2.0 switched DynamicUser to the static sni-router user, and the new
# 0600 config is unreadable under the old unit). Customize via drop-ins
# (systemctl edit sni-router), which survive this rewrite.
echo "==> installing systemd unit"
cat > "$UNIT" <<'EOF'
[Unit]
Description=sni-router - SNI-based L4 router
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/lib/sni-router/sni-router
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
User=sni-router
Group=sni-router
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# On an update, restart the service if it's currently running so the new binary
# takes over. try-restart is a no-op when the service is stopped.
if [ "$UPDATE" -eq 1 ] && systemctl is-active --quiet sni-router; then
  echo "==> restarting running service onto the new binary"
  systemctl try-restart sni-router
fi

# On a fresh install the only bind is the API on a port we picked as free, so
# it's safe to start right away — the web UI needs it reachable immediately.
if [ "$FRESH_CONFIG" -eq 1 ]; then
  echo "==> enabling and starting the service"
  systemctl enable --now sni-router
fi

echo
if [ "$UPDATE" -eq 1 ]; then
  echo "sni-router updated to $TAG at $BIN_DIR/sni-router (config left untouched)"
else
  echo "sni-router $TAG installed to $BIN_DIR/sni-router and started"

  if [ "$FRESH_CONFIG" -eq 1 ]; then
    # Best-effort primary IP for building a reachable API URL.
    PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$PRIMARY_IP" ] || PRIMARY_IP="<server-ip>"
    echo
    echo "=================  management API / web UI login  ================="
    echo "  url:      $API_SCHEME://$PRIMARY_IP:$API_PORT"
    echo "  bind:     $API_HOST:$API_PORT"
    echo "  token:    $API_TOKEN"
    echo "  header:   Authorization: Bearer $API_TOKEN"
    echo "  read:     GET  /status  /config  /healthz  /metrics  /version"
    echo "  write:    PUT  /config      (replace config, auto reload/restart)"
    echo "            POST /reload      (re-read config from disk)"
    echo "            POST /restart     (restart the service now)"
    echo "            POST /update      (update to the latest release, then restart)"
    echo "  example:  curl -s ${API_SCHEME}://${PRIMARY_IP}:${API_PORT}/status \\"
    echo "                 -H 'Authorization: Bearer $API_TOKEN'"
    echo "=================================================================="
    echo "  (token is stored in $CONF_DIR/sni-router.yaml under api.token)"
  fi
fi
