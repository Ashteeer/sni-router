#!/usr/bin/env bash
# Build sni-router on the remote build server over SSH (no CI available).
#
# Ships the last committed tree (git archive HEAD), so commit before deploying.
# Untracked files never leave this machine.
#
# Usage:
#   scripts/deploy.sh            upload + cargo build --release
#   scripts/deploy.sh --test     also run cargo test first
#
# Server settings come from .env in the repo root (see .env.example).
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] && . ./.env
: "${SSH_DEST:?set SSH_DEST in .env (ssh alias or user@host), see .env.example}"
SSH_PORT="${SSH_PORT:-22}"
REMOTE_DIR="${REMOTE_DIR:-~/build/sni-router}"

run() { ssh -p "$SSH_PORT" "$SSH_DEST" "$1"; }

# Make cargo visible in non-login shells (rustup installs into ~/.cargo).
CARGO='. "$HOME/.cargo/env" 2>/dev/null || true; cargo'

echo "==> uploading committed tree to $SSH_DEST:$REMOTE_DIR"
git archive HEAD | run "mkdir -p $REMOTE_DIR && tar -x -C $REMOTE_DIR"

if [ "${1:-}" = "--test" ]; then
  echo "==> cargo test"
  run "cd $REMOTE_DIR && $CARGO test >test.log 2>&1 \
       && tail -n 20 test.log \
       || { tail -n 60 test.log; exit 1; }"
fi

echo "==> cargo build --release"
if run "cd $REMOTE_DIR && $CARGO build --release >build.log 2>&1"; then
  run "cd $REMOTE_DIR && ls -lh target/release/sni-router \
       && echo \"remote binary: \$(pwd)/target/release/sni-router\""
  echo "==> build OK"
else
  echo "==> build FAILED, relevant output:"
  run "cd $REMOTE_DIR && grep -E '^(error|warning)' -m 40 -A 3 build.log || tail -n 40 build.log"
  exit 1
fi
