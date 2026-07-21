#!/usr/bin/env bash
# Binary-level proof that the SHIPPED openshield-engine actually runs the observe
# path (audit finding #1 — "the product does not run, only its components do").
#
# It builds the real openshield-engine + openshield-worker, runs the engine
# process against a temp watch dir with the dev Postgres, drops a file containing
# a valid CPF into the watched directory, and asserts an ALERT lands in the
# forward-secure ledger — exercising process boundaries, env config, the worker
# subprocess and the real ledger, which package tests cannot.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO"
DSN="postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"
WORK="$(mktemp -d)"
psql(){ podman exec openshield-pg psql -U openshield -tAqc "$1"; }

cleanup(){
  [ -n "${ENGINE_PID:-}" ] && kill "$ENGINE_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building the shipped binaries"
go build -o "$WORK/openshield-engine" ./cmd/openshield-engine
go build -o "$WORK/openshield-worker" ./cmd/openshield-worker
go build -o "$WORK/openshield-anchor" ./cmd/openshield-anchor
go build -o "$WORK/openshield-provision" ./cmd/openshield-provision
go build -o "$WORK/openshieldctl" ./cmd/openshieldctl

echo "==> dev Postgres up + clean ledger"
podman start openshield-pg >/dev/null 2>&1 || true
for i in $(seq 1 30); do podman exec openshield-pg pg_isready -U openshield >/dev/null 2>&1 && break; sleep 1; done
psql 'DROP TABLE IF EXISTS audit_entries, key_epochs, anchors, schema_migrations CASCADE' >/dev/null

WATCH="$WORK/watch"; mkdir -p "$WATCH"

echo "==> starting the engine binary (observe path, unprivileged notify-mode)"
OPENSHIELD_DSN="$DSN" \
OPENSHIELD_WORKER_BIN="$WORK/openshield-worker" \
OPENSHIELD_SIGNER_FILE="$WORK/signer.state" \
OPENSHIELD_WATCH_DIRS="$WATCH" \
  "$WORK/openshield-engine" >"$WORK/engine.log" 2>&1 &
ENGINE_PID=$!
for i in $(seq 1 30); do grep -q "engine observing" "$WORK/engine.log" 2>/dev/null && break; sleep 1; done
grep -q "engine observing" "$WORK/engine.log" || { echo "!! engine did not start observing" >&2; cat "$WORK/engine.log" >&2; exit 1; }

echo "==> dropping a file with a valid CPF into the watched dir"
printf 'name,cpf\nalice,111.444.777-35\n' > "$WATCH/customers.csv"

echo "==> asserting an ALERT (action=2) lands in the ledger"
ok=""
for i in $(seq 1 20); do
  n="$(psql "SELECT count(*) FROM audit_entries WHERE action = 2")"
  if [ "$n" -ge 1 ] 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { echo "!! no ALERT recorded by the running engine binary" >&2; cat "$WORK/engine.log" >&2; exit 1; }

echo "==> operational anchoring (D64): witness the head, then verify completeness is anchored"
"$WORK/openshield-provision" witness-keygen --out "$WORK/w" >/dev/null 2>&1
before="$("$WORK/openshieldctl" verify --dsn "$DSN" --witness "$WORK/w/witness-pub" 2>&1 | grep -oE 'completeness=[a-z]+' | head -1)"
"$WORK/openshield-anchor" --dsn "$DSN" --witness "$WORK/w/witness-priv" 2>&1 | grep -q 'witnessed head' || { echo "!! anchor tool did not witness the head" >&2; exit 1; }
after="$("$WORK/openshieldctl" verify --dsn "$DSN" --witness "$WORK/w/witness-pub" 2>&1 | grep -oE 'completeness=[a-z]+' | head -1)"
echo "   completeness before=$before after=$after"
echo "$after" | grep -q 'anchored' || { echo "!! completeness is not anchored after running openshield-anchor (before=$before after=$after)" >&2; exit 1; }
echo "   OK: openshield-anchor binary witnessed the head; openshieldctl verify reports anchored"

echo ""
echo "OBSERVE E2E PASSED: the shipped openshield-engine binary watched a dir, classified a real"
echo "file, decided ALERT, recorded it in the forward-secure ledger, and the openshield-anchor"
echo "binary witnessed the head so completeness verifies as anchored — end to end, as binaries."
