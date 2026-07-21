#!/usr/bin/env bash
# The core must not depend on any concrete capability (T-014, D26).
#
# The project's central claim is that a capability is a plugin: adding one never
# edits the core. The machine-checkable core of that claim is direction — if
# internal/core cannot even NAME a connector, classifier, policy, enforcer or
# store, it cannot depend on one, and adding one cannot require touching core.
#
# This is necessary, NOT sufficient. A capability can still reach around the bus
# into shared state (D26's worked example: Policy querying the analytics store).
# That is guarded elsewhere (State carries no handles; the enforcer-isolation
# compile-fail) and, ultimately, by a reviewer. Green here is not validation of
# the architecture. See internal/fitness and docs/design-t004-peer-ueba.md.
set -euo pipefail

BANNED_RE='openshield/internal/(connectors|enforcers|classify|policy|store|analytics|engine)'
deps="$(go list -deps ./internal/core 2>/dev/null || true)"

if [ -z "$deps" ]; then
  echo "check-capability-boundary: could not compute dependencies" >&2
  exit 2
fi

if hits="$(echo "$deps" | grep -E "$BANNED_RE" || true)"; [ -n "$hits" ]; then
  echo "FAIL: internal/core depends on a concrete capability it must not know about:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  echo >&2
  echo "The core defines contracts (Stage, Enforcer, Transport, Ledger); capabilities" >&2
  echo "implement them from outside. If core needs to import one, the boundary the" >&2
  echo "whole architecture rests on has been crossed." >&2
  exit 1
fi

echo "ok: internal/core depends on no concrete capability"
