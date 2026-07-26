#!/usr/bin/env bash
# PLAT-9: back up the system of record.
#
# This wraps the database's OWN tool rather than reimplementing it: pg_dump is what an operator's DBA
# already trusts and already monitors. What is added is the argument set (so it is not retyped from a
# wiki) and the reminder that a backup is only half of the pair.
#
# A BACKUP YOU HAVE NEVER RESTORED IS NOT A BACKUP. Run scripts/restore-drill.sh against a scratch
# database on a schedule; it is the half that tells you whether these files are evidence or bytes.
set -euo pipefail
: "${OPENSHIELD_DSN:?set OPENSHIELD_DSN}"
OUT=${1:-openshield-$(date -u +%Y%m%dT%H%M%SZ).dump}
pg_dump --format=custom --no-owner --no-privileges --file="$OUT" "$OPENSHIELD_DSN"
echo "wrote $OUT"
echo "NOTE: also back up each agent's forward-secure ledger state and the witness/anchor keys — the dump"
echo "      alone cannot be VERIFIED without the anchor it is checked against."
