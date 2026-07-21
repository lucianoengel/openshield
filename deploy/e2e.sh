#!/usr/bin/env bash
# Real container end-to-end test (T-023 e2e).
#
# Brings up the compose stack (Postgres + NATS + the openshield-server BINARY in a
# container), publishes telemetry over the real NATS, verifies it lands in the real
# Postgres, then tears down — restoring the dev Postgres the unit tests use. One
# command, clean before and after (teardown runs on any exit).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
PC="${PODMAN_COMPOSE:-/home/coder/.venv-podman-compose/bin/podman-compose}"
EVENT_ID="e2e-$$-$(date +%s 2>/dev/null || echo run)"

cleanup() {
  echo "==> tearing down"
  $PC down >/dev/null 2>&1 || true
  # Restore the dev Postgres the unit tests use (compose freed the port).
  podman start openshield-pg >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> freeing port 55432 (stopping dev openshield-pg)"
podman stop openshield-pg >/dev/null 2>&1 || true

echo "==> bringing up the stack (building the server image)"
$PC up -d --build >/dev/null 2>&1

echo "==> waiting for the server to subscribe"
ready=""
for _ in $(seq 1 60); do
  if $PC logs server 2>&1 | grep -q "subscribing to telemetry" \
     || podman logs openshield_server_1 2>&1 | grep -q "subscribing to telemetry"; then
    ready=1; break
  fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "!! server did not become ready" >&2
  $PC logs server 2>&1 | tail -20 || podman logs openshield_server_1 2>&1 | tail -20 || true
  exit 1
fi
echo "==> server ready; running the e2e test (event id $EVENT_ID)"

OPENSHIELD_E2E_EVENT="$EVENT_ID" \
  go test -tags e2e -count=1 -v ./e2e/...
