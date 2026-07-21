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

echo "==> installing systemd units"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-agent.service  "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-worker.service "$UNIT_DIR/"
install -m 0644 "$REPO_ROOT"/deploy/systemd/openshield-server.service "$UNIT_DIR/"

echo "==> installing hardening drop-ins"
install -d "$UNIT_DIR/openshield-worker.service.d"
install -m 0644 "$REPO_ROOT/deploy/openshield-worker.service.d-hardening.conf" \
  "$UNIT_DIR/openshield-worker.service.d/hardening.conf"
install -d "$UNIT_DIR/openshield-agent.service.d"
install -m 0644 "$REPO_ROOT/deploy/openshield-agent.service.d-heartbeat.conf" \
  "$UNIT_DIR/openshield-agent.service.d/heartbeat.conf"

echo "==> reloading systemd"
systemctl daemon-reload

echo "==> enabling services (server + worker; the agent is enabled but NOT started)"
systemctl enable openshield-server.service openshield-worker.service openshield-agent.service

cat <<'DONE'

OpenShield installed.

  - openshield-server / openshield-worker: enabled.
  - openshield-agent: enabled but NOT started (start it once fanotify marks are
    configured for this host):  systemctl start openshield-agent

Upgrade: rebuild, re-run this installer, then `systemctl restart openshield-agent`.
Restarting the agent is safe under load — the fail-open watchdog (D18) answers the
kernel regardless of pipeline state, so a restart cannot hang a blocked process.
DONE
