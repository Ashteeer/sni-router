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
#                                        # default_tls (and serve the admin API
#                                        # over HTTPS so a web UI can reach it)
#
# Re-running updates the binary in place without touching the config. Pass
# --reinstall to also overwrite the config and systemd unit from scratch.
#
# On a fresh install the service is installed but NOT started: edit the config
# and pick bind addresses that don't clash with services already on the machine.
# A random admin token is generated and printed so a web UI can log in later.
set -euo pipefail

REPO="Ashteeer/sni-router"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/sni-router"
UNIT="/etc/systemd/system/sni-router.service"
ADMIN_PORT=9000

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
[ -x "$BIN_DIR/sni-router" ] && [ "$REINSTALL" -eq 0 ] && UPDATE=1

ASSET="sni-router-$TAG-$ARCH-linux.tar.gz"
echo "==> downloading $ASSET"
dl "https://github.com/$REPO/releases/download/$TAG/$ASSET" "$TMP/$ASSET"
tar -xzf "$TMP/$ASSET" -C "$TMP"
install -m 0755 "$TMP/sni-router" "$BIN_DIR/sni-router"

mkdir -p "$CONF_DIR"
# Config: keep the user's on update; (re)write it only on a fresh install or --reinstall.
FRESH_CONFIG=0
ADMIN_TOKEN=""
ADMIN_SCHEME="http"
ADMIN_HOST="127.0.0.1"     # loopback by default; 0.0.0.0 only when served over TLS
if [ ! -f "$CONF_DIR/sni-router.yaml" ] || [ "$REINSTALL" -eq 1 ]; then
  echo "==> installing default config to $CONF_DIR/sni-router.yaml"
  dl "https://raw.githubusercontent.com/$REPO/main/config/sni-router.example.yaml" \
     "$CONF_DIR/sni-router.yaml"
  FRESH_CONFIG=1

  # Generate a random admin token so the write API (and a future web UI) is
  # usable and authenticated out of the box.
  if command -v openssl >/dev/null 2>&1; then
    ADMIN_TOKEN="$(openssl rand -hex 24)"
  else
    ADMIN_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi

  # With a cert, wire default_tls and expose the admin API over HTTPS on all
  # interfaces (so a remote web UI can reach it). Without a cert, keep the admin
  # API on loopback (reach it via an SSH tunnel).
  if [ -n "$CERT" ]; then
    ADMIN_SCHEME="https"
    ADMIN_HOST="0.0.0.0"
    cat >> "$CONF_DIR/sni-router.yaml" <<EOF

# --- added by install.sh: shared TLS cert (also used by the admin API) ---
default_tls:
  cert: "$CERT"
  key: "$KEY"
EOF
  fi

  cat >> "$CONF_DIR/sni-router.yaml" <<EOF

# --- added by install.sh: admin/REST API (read + write) ---
admin:
  bind: "$ADMIN_HOST:$ADMIN_PORT"
  token: "$ADMIN_TOKEN"
EOF
  # The config now holds the admin token — keep it out of reach of other local
  # users. systemd's ConfigurationDirectory= chowns /etc/sni-router (and its
  # contents) to the service's DynamicUser on start, so the service can still
  # read and rewrite it.
  chmod 600 "$CONF_DIR/sni-router.yaml"
else
  echo "==> keeping existing config $CONF_DIR/sni-router.yaml"
fi

if [ ! -f "$UNIT" ] || [ "$REINSTALL" -eq 1 ]; then
  echo "==> installing systemd unit"
  cat > "$UNIT" <<'EOF'
[Unit]
Description=sni-router - SNI-based L4 router
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/sni-router
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
DynamicUser=yes
# Own /etc/sni-router as the (dynamic) service user so `PUT /config` from the
# admin API can rewrite the config file in place.
ConfigurationDirectory=sni-router
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
fi

# On an update, restart the service if it's currently running so the new binary
# takes over. try-restart is a no-op when the service is stopped.
if [ "$UPDATE" -eq 1 ] && systemctl is-active --quiet sni-router; then
  echo "==> restarting running service onto the new binary"
  systemctl try-restart sni-router
fi

echo
if [ "$UPDATE" -eq 1 ]; then
  echo "sni-router updated to $TAG at $BIN_DIR/sni-router (config left untouched)"
else
  echo "sni-router $TAG installed to $BIN_DIR/sni-router"
  echo "Next steps:"
  echo "  1. edit $CONF_DIR/sni-router.yaml (pick bind addresses that are actually free: ss -tlnp)"
  echo "  2. validate:  sni-router -t"
  echo "  3. start:     systemctl enable --now sni-router"

  if [ "$FRESH_CONFIG" -eq 1 ]; then
    # Best-effort primary IP for building a reachable admin URL.
    PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$PRIMARY_IP" ] || PRIMARY_IP="<server-ip>"
    if [ "$ADMIN_HOST" = "0.0.0.0" ]; then ADMIN_URL_HOST="$PRIMARY_IP"; else ADMIN_URL_HOST="127.0.0.1"; fi
    echo
    echo "=================  admin API / web UI login  ================="
    echo "  url:      $ADMIN_SCHEME://$ADMIN_URL_HOST:$ADMIN_PORT"
    echo "  bind:     $ADMIN_HOST:$ADMIN_PORT"
    echo "  token:    $ADMIN_TOKEN"
    echo "  header:   Authorization: Bearer $ADMIN_TOKEN"
    echo "  read:     GET  /status  /config  /healthz"
    echo "  write:    PUT  /config      (replace config, auto reload/restart)"
    echo "            POST /reload      (re-read config from disk)"
    echo "            POST /restart     (restart the service now)"
    if [ "$ADMIN_HOST" = "127.0.0.1" ]; then
      echo "  note:     admin API is loopback-only (no cert given). For remote"
      echo "            access use an SSH tunnel, or re-run with --cert/--key to"
      echo "            serve it over HTTPS on all interfaces."
    fi
    echo "  example:  curl -s ${ADMIN_SCHEME}://${ADMIN_URL_HOST}:${ADMIN_PORT}/status \\"
    echo "                 -H 'Authorization: Bearer $ADMIN_TOKEN'"
    echo "============================================================="
    echo "  (token is stored in $CONF_DIR/sni-router.yaml under admin.token)"
  fi
fi
