#!/usr/bin/env bash
# OpenShield installer (T-027) — idempotent, from a built tree to enabled units.
#
# Manual multi-step installation is where a privilege boundary gets skipped; this
# script does it right every time. It installs the binaries, creates the
# unprivileged worker user, places the systemd units and hardening drop-ins, and
# reloads systemd. Re-running it updates in place.
#
# It refuses to run without root (installing units needs it) and does NOT
# auto-start the agent — fanotify on an unconfigured host is the operator's call.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root (it installs systemd units and creates users)." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system

echo "==> building binaries"
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-agent"  ./cmd/openshield-agent )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-worker" ./cmd/openshield-worker )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-server" ./cmd/openshield-server )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-engine"    ./cmd/openshield-engine )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-gateway"   ./cmd/openshield-gateway )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-anchor"    ./cmd/openshield-anchor )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshield-provision" ./cmd/openshield-provision )
( cd "$REPO_ROOT" && go build -o "$BIN_DIR/openshieldctl"     ./cmd/openshieldctl )

# Create system users if absent (idempotent).
ensure_user() {
  local user="$1"
  if ! id -u "$user" >/dev/null 2>&1; then
    echo "==> creating system user $user"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
}
ensure_user openshield
ensure_user openshield-worker
ensure_user openshield-engine
ensure_user openshield-gateway

echo "==> installing systemd units"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-agent.service  "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-worker.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-server.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-engine.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-gateway.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-anchor.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-anchor.timer   "$UNIT_DIR/"

echo "==> installing hardening drop-ins"
install -d "$UNIT_DIR/openshield-worker.service.d"
install -m 0644 "$REPO_ROOT/deploy/openshield-worker.service.d-hardening.conf" \
  "$UNIT_DIR/openshield-worker.service.d/hardening.conf"
install -d "$UNIT_DIR/openshield-agent.service.d"
install -m 0644 "$REPO_ROOT/deploy/openshield-agent.service.d-heartbeat.conf" \
  "$UNIT_DIR/openshield-agent.service.d/heartbeat.conf"

echo "==> reloading systemd"
systemctl daemon-reload

echo "==> enabling services (server + worker + engine + gateway; the agent is a DEFERRED stub, not enabled)"
systemctl enable openshield-server.service openshield-worker.service openshield-engine.service openshield-gateway.service

cat <<'DONE'

OpenShield installed.

  - openshield-server / openshield-worker / openshield-engine / openshield-gateway: enabled.
    The engine observes OPENSHIELD_WATCH_DIRS; the gateway is observe-only until you
    set OPENSHIELD_ENFORCE (D1). Both run under their own isolated users (D68).
  - openshield-agent: installed but NOT enabled. It is the DEFERRED inline-blocking
    component (D49) and is a STUB today (it exits non-zero); do not enable it until the
    real agent ships.

Upgrade: rebuild, re-run this installer, then restart the changed services.
DONE
