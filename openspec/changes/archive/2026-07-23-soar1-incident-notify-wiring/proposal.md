## Why

`MaterializeIncidents` correlates a subject's alert burst into a persisted incident, but it never
notifies anyone — a materialized incident sits in the `incidents` table until an analyst polls for
it. That defeats the SOAR delivery target ("no incident waits for a human to poll") and is the last
open thread of the R34-13 tail ("incidents never `emit` = promote SOAR-1"). SOAR-1 wires the
already-built async notification path (SIEM-12 / durable-notification-dedup) to incident creation, so
a new incident pages exactly once, automatically. It also unblocks SOAR-2 (scheduled correlation) and
pending audit test #10 (incident→notify).

## What Changes

- When `MaterializeIncidents` creates a **new** incident (a genuine INSERT), the control plane emits
  exactly one notification for it.
- Re-materializing the **same** open incident (the `ON CONFLICT ... DO UPDATE` extend-the-burst path)
  emits **zero** notifications — the update is not a new incident.
- The notification carries a new `KindIncident` and is keyed by the **incident id** (e.g. `inc_<id>`),
  not by the content-window idempotency key: dedup is per-incident, so a fresh incident for the same
  subject after the first is acknowledged/closed pages again.
- Delivery rides the existing best-effort, off-ingest `emit → deliverLoop` async path and its two-tier
  idempotency (in-memory `dedupeSet` + durable `notify_dedupe`); a client-timeout-after-success retry
  and a same-id re-emit both dedupe.
- The notification is pseudonymous (subject, peak risk, severity, a short detail) — no content.
- No new intent verbs, no actuation, no incident state machine beyond what already exists (ADR-12
  Tier-1; the state machine is SOAR-2).

## Capabilities

### New Capabilities
<!-- none — this folds into the existing control-plane capability that already owns both incident
     materialization and notification delivery -->

### Modified Capabilities
- `control-plane`: the "Correlated incidents are materialized with identity and state" requirement
  now also specifies that **materializing a NEW incident delivers exactly one notification, and
  re-materializing the same open incident delivers none**, keyed by the incident id.

## Impact

- **Code:** `internal/controlplane/incidents.go` (`MaterializeIncidents` returns insert-vs-update per
  incident and emits on insert); `internal/notify/notify.go` (add `KindIncident`). No proto change
  (`Kind` is a string const). No migration (`incidents`/`notify_dedupe` already exist).
- **Behavior:** a deployer with a configured webhook now gets paged on incident creation; with no sink
  configured (`Nop`, no `deliverLoop`), nothing changes — emit is a no-op unless `SetNotifier` ran.
- **Tests:** real Postgres + an `httptest` webhook end-to-end — drive `MaterializeIncidents` twice,
  assert exactly one POST; plus a distinct-second-incident pages again. Mutation-verified.
