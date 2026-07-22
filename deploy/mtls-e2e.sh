#!/usr/bin/env bash
# Mutual-TLS fleet path across real containers (D55).
#
# Focused companion to fleet-e2e.sh: brings up Postgres + a TLS NATS + the control
# plane with mutual TLS on both agent-facing channels, and ASSERTS:
#   - an agent WITH a CA-issued client cert enrolls (over HTTPS) and publishes
#     VERIFIED telemetry (over TLS NATS);
#   - an agent WITHOUT a client cert is REFUSED — no verified telemetry appears.
#
# It deliberately does not re-run the whole fleet suite (dead-man's-switch,
# revocation, peer-UEBA) — those are covered plaintext in fleet-e2e.sh; this
# isolates the channel-security layer. Tears down and restores the dev Postgres.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO"
NET=osmtls
PG=osmtls-pg; NATS=osmtls-nats; SRV=osmtls-server
CERTS="$(mktemp -d)"
psql(){ podman exec "$PG" psql -U openshield -tAqc "$1"; }

cleanup(){
  echo "==> teardown"
  podman rm -f osmtls-agent-ok osmtls-agent-nocert "$SRV" "$NATS" "$PG" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$CERTS"
  podman start openshield-pg >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> generating a throwaway CA + role-tagged certs via openshield-provision (D60)"
# Use the real provisioning tool, not hand-rolled openssl — this proves the tool's
# output actually works with the server, the role gate, and the TLS NATS broker.
PROV="$(mktemp)"
go build -o "$PROV" ./cmd/openshield-provision
"$PROV" ca-init --out "$CERTS" >/dev/null
# Server cert — SANs cover both service container names + localhost + 127.0.0.1;
# usable as server (enroll HTTPS, NATS TLS) AND client (server→NATS). Role is
# irrelevant for the server leg; tag it agent.
"$PROV" cert --ca "$CERTS" --role agent --cn osmtls-server \
  --san osmtls-server --san osmtls-nats --san localhost --san 127.0.0.1 --out "$CERTS/srv" >/dev/null
mv "$CERTS/srv/cert.pem" "$CERTS/server-cert.pem"; mv "$CERTS/srv/key.pem" "$CERTS/server-key.pem"
# Agent client cert (OU=agent): may /enroll, may NOT /view.
"$PROV" cert --ca "$CERTS" --role agent --cn osmtls-agent --out "$CERTS/ag" >/dev/null
mv "$CERTS/ag/cert.pem" "$CERTS/client-cert.pem"; mv "$CERTS/ag/key.pem" "$CERTS/client-key.pem"
# Operator client cert (OU=operator): may /view, may NOT /enroll.
"$PROV" cert --ca "$CERTS" --role operator --cn osmtls-op --out "$CERTS/op2" >/dev/null
mv "$CERTS/op2/cert.pem" "$CERTS/op-cert.pem"; mv "$CERTS/op2/key.pem" "$CERTS/op-key.pem"
rm -f "$PROV"
chmod 644 "$CERTS"/*.pem
chmod 755 "$CERTS" # mktemp -d is 0700; the container's nonroot user must traverse it

echo "==> building images"
podman build -q -t openshield-server:fleet -f Containerfile . >/dev/null
podman build -q -t openshield-fleet-agent:latest -f Containerfile.fleet-agent . >/dev/null

echo "==> bringing up control plane over mutual TLS"
podman stop openshield-pg >/dev/null 2>&1 || true
podman network create "$NET" >/dev/null 2>&1 || true
podman run -d --name "$PG" --network "$NET" -e POSTGRES_USER=openshield -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=openshield docker.io/library/postgres:16 >/dev/null
# NATS with mutual TLS: verify client certs against our CA.
podman run -d --name "$NATS" --network "$NET" -v "$CERTS:/certs:ro,Z" docker.io/library/nats:2 \
  --tls --tlscert /certs/server-cert.pem --tlskey /certs/server-key.pem \
  --tlsverify --tlscacert /certs/ca.pem >/dev/null
for i in $(seq 1 30); do podman exec "$PG" pg_isready -U openshield >/dev/null 2>&1 && break; sleep 1; done
echo "==> migrating as OWNER + provisioning the non-owner app role (SEC-6/PLAT-6b)"
podman run --rm --network "$NET" -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" -e OPENSHIELD_APP_ROLE=openshield_app -e OPENSHIELD_APP_PASSWORD=app openshield-server:fleet openshield-server migrate
podman run -d --name "$SRV" --network "$NET" -p 18080:8080 -v "$CERTS:/certs:ro,Z" \
  -e OPENSHIELD_DSN="postgres://openshield_app:app@$PG:5432/openshield?sslmode=disable" \
  -e OPENSHIELD_NATS_URL="tls://$NATS:4222" -e OPENSHIELD_HTTP_ADDR=":8080" \
  -e OPENSHIELD_TLS_CA=/certs/ca.pem -e OPENSHIELD_TLS_CERT=/certs/server-cert.pem -e OPENSHIELD_TLS_KEY=/certs/server-key.pem \
  openshield-server:fleet >/dev/null
for i in $(seq 1 30); do podman logs "$SRV" 2>&1 | grep -q "subscribing to telemetry" && break; sleep 1; done
podman logs "$SRV" 2>&1 | grep -q "mutual TLS enabled" || { echo "!! server did not enable mutual TLS" >&2; exit 1; }
echo "==> control plane up (mutual TLS)"

echo "==> agent WITH a client cert: expect enrollment + verified telemetry"
tok="$(podman exec -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" "$SRV" openshield-server issue-token 3600)"
podman run -d --name osmtls-agent-ok --network "$NET" -v "$CERTS:/certs:ro,Z" \
  -e OPENSHIELD_AGENT_ID="agent-ok" -e OPENSHIELD_ENROLL_URL="https://$SRV:8080/enroll" \
  -e OPENSHIELD_ENROLL_TOKEN="$tok" -e OPENSHIELD_NATS_URL="tls://$NATS:4222" -e OPENSHIELD_HEARTBEAT="1s" \
  -e OPENSHIELD_TLS_CA=/certs/ca.pem -e OPENSHIELD_TLS_CERT=/certs/client-cert.pem -e OPENSHIELD_TLS_KEY=/certs/client-key.pem \
  openshield-fleet-agent:latest >/dev/null
ok=""
for i in $(seq 1 25); do
  n="$(psql "SELECT count(*) FROM fleet_telemetry WHERE verified=true AND agent_id='agent-ok'")"
  if [ "$n" -ge 1 ] 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { echo "!! agent-ok produced no verified telemetry over mTLS" >&2; podman logs osmtls-agent-ok 2>&1 | tail -5 >&2; exit 1; }
echo "   OK: agent-ok enrolled over HTTPS and published verified telemetry over TLS NATS"

echo "==> agent WITHOUT a client cert: expect refusal (no verified telemetry)"
tok2="$(podman exec -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" "$SRV" openshield-server issue-token 3600)"
# TLS disabled on the agent → plaintext HTTP/NATS against TLS endpoints → refused.
podman run -d --name osmtls-agent-nocert --network "$NET" \
  -e OPENSHIELD_AGENT_ID="agent-nocert" -e OPENSHIELD_ENROLL_URL="http://$SRV:8080/enroll" \
  -e OPENSHIELD_ENROLL_TOKEN="$tok2" -e OPENSHIELD_NATS_URL="nats://$NATS:4222" -e OPENSHIELD_HEARTBEAT="1s" \
  openshield-fleet-agent:latest >/dev/null
sleep 8
nc="$(psql "SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-nocert'")"
[ "$nc" = "0" ] || { echo "!! agent without a client cert got $nc telemetry rows through — mTLS not enforced" >&2; exit 1; }
echo "   OK: agent-nocert refused (0 telemetry rows) — no plaintext downgrade"

echo "==> cert-role authorization (D58): agent≠operator across /enroll and /view"
# Reachable from the host via the published port; server cert SAN includes localhost.
C=(--cacert "$CERTS/ca.pem" -s -o /dev/null -w '%{http_code}' --max-time 5)
AG=(--cert "$CERTS/client-cert.pem" --key "$CERTS/client-key.pem")   # OU=agent
OP=(--cert "$CERTS/op-cert.pem" --key "$CERTS/op-key.pem")           # OU=operator
optok="$(podman exec -e OPENSHIELD_DSN="postgres://openshield:dev@$PG:5432/openshield?sslmode=disable" "$SRV" openshield-server issue-token 3600)"
enroll_body='{"token":"'"$optok"'","agent_id":"role-probe","public_key":"AAAA"}'

# An OPERATOR cert must NOT be able to enroll (403).
op_enroll="$(curl "${C[@]}" "${OP[@]}" -X POST -H 'content-type: application/json' -d "$enroll_body" https://localhost:18080/enroll)"
[ "$op_enroll" = "403" ] || { echo "!! operator cert on /enroll = $op_enroll, want 403" >&2; exit 1; }
# An AGENT cert must NOT be able to view (403) — the D56 hole, now closed.
ag_view="$(curl "${C[@]}" "${AG[@]}" https://localhost:18080/view?event=nope)"
[ "$ag_view" = "403" ] || { echo "!! agent cert on /view = $ag_view, want 403 (D56 hole open!)" >&2; exit 1; }
# The OPERATOR cert IS allowed on /view (200 even for a missing event → empty rows).
op_view="$(curl "${C[@]}" "${OP[@]}" https://localhost:18080/view?event=nope)"
[ "$op_view" = "200" ] || { echo "!! operator cert on /view = $op_view, want 200" >&2; exit 1; }
echo "   OK: operator /enroll=403, agent /view=403, operator /view=200 — roles enforced"

echo ""
echo "MUTUAL-TLS E2E PASSED: cert-bearing agent enrolls + verified telemetry; no-cert agent refused; roles enforced"
