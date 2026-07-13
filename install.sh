#!/usr/bin/env bash
# sni-router installer / updater: downloads a release binary and sets up systemd.
#
# Usage:
#   wget https://raw.githubusercontent.com/Ashteeer/sni-router/main/install.sh
#   less install.sh        # always read scripts before running them as root
#   sudo bash install.sh                 # install, or update in place (keeps config)
#   sudo bash install.sh -v 1.1.0        # install/update a specific version
#   sudo bash install.sh --reinstall     # wipe and reinstall everything (incl. config)
#
# Re-running updates the binary in place without touching the config. Pass
# --reinstall to also overwrite the config and systemd unit from scratch.
#
# On a fresh install the service is installed but NOT started: edit the config
# and pick bind addresses that don't clash with services already on the machine.
set -euo pipefail

REPO="Ashteeer/sni-router"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/sni-router"
UNIT="/etc/systemd/system/sni-router.service"

VERSION=""
REINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    -v|--version) VERSION="${2:-}"; [ -n "$VERSION" ] || { echo "error: -v needs a version"; exit 1; }; shift 2 ;;
    --reinstall)  REINSTALL=1; shift ;;
    -h|--help)    sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "error: unknown argument \"$1\" (see --help)"; exit 1 ;;
  esac
done

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
if [ ! -f "$CONF_DIR/sni-router.yaml" ] || [ "$REINSTALL" -eq 1 ]; then
  echo "==> installing default config to $CONF_DIR/sni-router.yaml"
  dl "https://raw.githubusercontent.com/$REPO/main/config/sni-router.example.yaml" \
     "$CONF_DIR/sni-router.yaml"
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
fi
