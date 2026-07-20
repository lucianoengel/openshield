#!/usr/bin/env bash
# internal/core must not depend on a message broker or a network transport.
#
# The endpoint pipeline is in-process by measurement, not by preference:
# T-002 measured the fanotify permission window at 1-3us typical / 532us worst
# case while a real process sits blocked in TASK_UNINTERRUPTIBLE. A broker round
# trip does not fit. Stating that in a comment would not keep it true; this does.
set -euo pipefail

# Databases join brokers and network transports: a storage dependency inside
# core would invite blocking work into the permission window.
BANNED_RE='nats-io|grpc|net/http|golang.org/x/net|jackc/pgx|database/sql|lib/pq'
deps="$(go list -deps ./internal/core 2>/dev/null || true)"

if [ -z "$deps" ]; then
  echo "check-core-deps: could not compute dependencies" >&2
  exit 2
fi

if hits="$(echo "$deps" | grep -E "$BANNED_RE" || true)"; [ -n "$hits" ]; then
  echo "FAIL: internal/core depends on transport packages it must not know about:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  echo >&2
  echo "The endpoint pipeline is in-process; NATS is the agent<->control-plane" >&2
  echo "boundary only. Reach transport through core.Transport instead." >&2
  exit 1
fi

echo "ok: internal/core has no broker, network transport or database dependency"
