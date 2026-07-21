## Why

SEC-3 (P0, absorbing SEC-11). `Overdue`/`LastSeen` aggregated `fleet_telemetry` WITHOUT
filtering `verified` — so a dead/compromised agent could be kept "alive" indefinitely by
anyone who can publish unsigned telemetry with a self-asserted agent_id, and unverified rows
polluted operator views. And `LastSeen` swallowed ALL DB errors as "agent unknown" (SEC-11),
so a down database read as agent absence — silently hiding the whole fleet.

## What Changes

- `Overdue`: derive liveness from the ROSTER (`agent_identities`, non-revoked) LEFT JOINed to
  last VERIFIED telemetry — only verified rows count, and an enrolled-but-silent (or purged)
  agent still surfaces as overdue instead of vanishing.
- `LastSeen`: filter `verified = true`; distinguish a DB ERROR from AGENT ABSENCE (SEC-11) —
  a query error is returned as an error, a NULL max as not-found.

## Capabilities

### Modified Capabilities
- `heartbeat`: the dead-man's-switch counts only verified telemetry, over the enrolled roster.

## Impact

- `internal/controlplane/heartbeat.go`; `docs/decisions.md` D115.
- Proven (Postgres): `LastSeen` finds a verified row but NOT an agent seen only via unverified
  telemetry, and an unknown agent is absence (not error); `Overdue` flags a stale agent, an
  enrolled-but-never-seen agent (roster fix), and an agent kept "fresh" ONLY by unverified
  telemetry (the dead-man's-switch holds), while a verified-fresh agent is not overdue; a DB
  error surfaces as an error, not absence (SEC-11 — proven by a closed pool). Guards
  mutation-tested (LastSeen/Overdue verified-filter dropped; LastSeen swallows DB error).
- NOT in scope (stated): deprecating/removing the unsigned ingest SUBSCRIPTIONS (the unsigned
  event/classification/decision/heartbeat subjects still store rows, but they are now
  verified=false and excluded from liveness + authoritative views — removing the subscriptions
  entirely is a follow-up); the operator VIEW (`/view`) filtering (this fixes liveness; view
  filtering is a small follow-up on the same predicate). Legitimate agents already send SIGNED
  heartbeats (fleet-agent uses SignedPublisher), so verified liveness works in production.
