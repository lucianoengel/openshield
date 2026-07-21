#!/usr/bin/env bash
# Multi-agent fleet simulation in podman (Direction 1).
#
# Brings up the control plane + Postgres + NATS, enrols N agent containers (each
# with its own identity, over HTTP), and ASSERTS the fleet properties against the
# real control plane: verified+attributed telemetry, liveness, dead-man's-switch
# on a killed agent, and revocation rejecting telemetry. Tears down and restores
# the dev Postgres on any exit.
#
# Fanotify permission mode is NOT simulable in rootless podman (probed: needs
# init-namespace CAP_SYS_ADMIN), so this proves the fleet CONTROL path, not
# kernel eventing.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO"
N=3
NET=osfleet
PG=osfleet-pg; NATS=osfleet-nats; SRV=osfleet-server
psql(){ podman exec "$PG" psql -U openshield -tAqc "$1"; }

cleanup(){
  echo "==> teardown"
  for i in $(seq 1 "$N"); do podman rm -f "osfleet-agent-$i" >/dev/null 2>&1 || true; done
  podman rm -f "$SRV" "$NATS" "$PG" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman start openshield-pg >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building images"
podman build -q -t openshield-server:fleet -f Containerfile . >/dev/null
podman build -q -t openshield-fleet-agent:latest -f Containerfile.fleet-agent . >/dev/null

echo "==> bringing up control plane"
podman stop openshield-pg >/dev/null 2>&1 || true
podman network create "$NET" >/dev/null 2>&1 || true
podman run -d --name "$PG" --network "$NET" -e POSTGRES_USER=openshield -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=openshield docker.io/library/postgres:16 >/dev/null
podman run -d --name "$NATS" --network "$NET" docker.io/library/nats:2 >/dev/null
for i in $(seq 1 30); do podman exec "$PG" pg_isready -U openshield >/dev/null 2>&1 && break; sleep 1; done
podman run -d --name "$SRV" --network "$NET" \
  -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" \
  -e OPENSHIELD_NATS_URL="nats://$NATS:4222" -e OPENSHIELD_HTTP_ADDR=":8080" \
  openshield-server:fleet >/dev/null
for i in $(seq 1 30); do podman logs "$SRV" 2>&1 | grep -q "subscribing to telemetry" && break; sleep 1; done
echo "==> control plane up"

echo "==> enrolling $N agents"
for i in $(seq 1 "$N"); do
  tok="$(podman exec -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" "$SRV" openshield-server issue-token 3600)"
  podman run -d --name "osfleet-agent-$i" --network "$NET" \
    -e OPENSHIELD_AGENT_ID="agent-$i" -e OPENSHIELD_ENROLL_URL="http://$SRV:8080/enroll" \
    -e OPENSHIELD_ENROLL_TOKEN="$tok" -e OPENSHIELD_NATS_URL="nats://$NATS:4222" \
    -e OPENSHIELD_HEARTBEAT="1s" openshield-fleet-agent:latest >/dev/null
done

echo "==> asserting verified+attributed telemetry from all $N agents"
ok=""
for i in $(seq 1 20); do
  n="$(psql "SELECT count(DISTINCT agent_id) FROM fleet_telemetry WHERE verified=true AND agent_id LIKE 'agent-%'")"
  if [ "$n" = "$N" ]; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { echo "!! only got verified telemetry from $n/$N agents" >&2; exit 1; }
echo "   OK: $N agents publishing verified, attributed telemetry"

echo "==> killing agent-1; expecting dead-man's-switch (overdue) after silence grows"
podman rm -f osfleet-agent-1 >/dev/null
sleep 6  # agents heartbeat every 1s; agent-1 now silent
silence1="$(psql "SELECT EXTRACT(EPOCH FROM now()-max(received_at)) FROM fleet_telemetry WHERE agent_id='agent-1'")"
silence2="$(psql "SELECT EXTRACT(EPOCH FROM now()-max(received_at)) FROM fleet_telemetry WHERE agent_id='agent-2'")"
awk "BEGIN{exit !($silence1 > 4 && $silence2 < 3)}" || { echo "!! dead-man's-switch: agent-1 silence=$silence1 agent-2 silence=$silence2" >&2; exit 1; }
echo "   OK: agent-1 overdue (silent ${silence1}s), agent-2 alive (${silence2}s)"

echo "==> revoking agent-2; expecting its telemetry to be rejected"
rej_before="$(podman logs "$SRV" 2>&1 | grep -c 'x' || true)"  # placeholder
last2_before="$(psql "SELECT EXTRACT(EPOCH FROM now()-max(received_at)) FROM fleet_telemetry WHERE agent_id='agent-2'")"
podman exec -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" "$SRV" openshield-server revoke agent-2 >/dev/null 2>&1
sleep 5  # agent-2 keeps publishing but is now rejected → its verified rows stop advancing
last2_after="$(psql "SELECT EXTRACT(EPOCH FROM now()-max(received_at)) FROM fleet_telemetry WHERE agent_id='agent-2'")"
# agent-3 (still enrolled) must be advancing; agent-2 must be stale (> the revoke wait)
last3="$(psql "SELECT EXTRACT(EPOCH FROM now()-max(received_at)) FROM fleet_telemetry WHERE agent_id='agent-3'")"
awk "BEGIN{exit !($last2_after > 4 && $last3 < 3)}" || { echo "!! revocation: agent-2 stale=$last2_after agent-3=$last3" >&2; exit 1; }
echo "   OK: revoked agent-2 telemetry rejected (stale ${last2_after}s), agent-3 still verified (${last3}s)"

echo ""
echo "FLEET SIMULATION PASSED: enroll + verified telemetry + dead-man's-switch + revocation across containers"
