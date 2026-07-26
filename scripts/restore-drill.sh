#!/usr/bin/env bash
# PLAT-9: restore, then PROVE the restore.
#
# THE POINT: a byte-perfect pg_restore that produces an unverifiable ledger is a FAILED restore — the
# bytes came back, the evidence did not. So this does not report success until `restore-verify` passes,
# and `set -e` means a failed restore never reaches the verification step (which could otherwise pass
# against whatever was already in the database — a green drill over a restore that never happened).
#
# The witness key is REQUIRED. Without an anchor to check against, TRUNCATION is undetectable, and
# truncation is the most likely way a restore loses evidence.
set -euo pipefail
: "${OPENSHIELD_DSN:?set OPENSHIELD_DSN (use a SCRATCH database — this is destructive)}"
: "${OPENSHIELD_WITNESS_PUB:?set OPENSHIELD_WITNESS_PUB — a drill that cannot detect truncation rehearses the wrong thing}"
DUMP=${1:?usage: restore-drill.sh <dump-file>}
ANCHOR=${OPENSHIELD_ANCHOR_PUB:-}

pg_restore --clean --if-exists --exit-on-error --no-owner --no-privileges --dbname="$OPENSHIELD_DSN" "$DUMP"

args=(restore-verify --dsn "$OPENSHIELD_DSN" --witness "$OPENSHIELD_WITNESS_PUB")
[ -n "$ANCHOR" ] && args+=(--anchor "$ANCHOR")
openshieldctl "${args[@]}"
echo "restore drill PASSED: the ledger re-verified against its anchors"
