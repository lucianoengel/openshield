# SIEM-1: event search over the fleet telemetry aggregate

## Why

The control plane persisted every received event, classification and decision into
`fleet_telemetry`, but the only ways to read that aggregate were two point-lookups —
everything for one agent, or everything for one event id. An investigator triaging a
correlated incident (D65/D131) needs the middle ground a SIEM's search bar provides:
"every DECISION in this window", "every event of this KIND for this agent", "only the
VERIFIED (attributable) rows". None of that was expressible, so the investigative loop
dead-ended at the correlation result.

## What Changes

- **`SearchTelemetry(ctx, EventFilter)`** — a filtered, bounded, newest-first search over
  `fleet_telemetry`. `EventFilter` constrains by agent, kind, event id, a `[since, until]`
  time window, and `VerifiedOnly` (attributable rows only — an investigator building a case
  must be able to exclude self-asserted telemetry, which is not evidence, D44). Every
  constraint is applied as **parameterized SQL** (operator input is data), and the limit is
  **hard-capped** at `maxSearchLimit` — the same SEC-8 discipline as the peer-alert search.
- **It returns metadata only** — agent, kind, event id, verified, time — not the payload blob.
  A list surface that dumped every raw proto would be noisy and unbounded; the caller drills
  into a specific event id via the existing `TelemetryForEvent` for the payload.
- **A `/events` endpoint** on the operator read surface, gated behind the operator role (D82),
  with the same fail-loud parse discipline (a malformed `since`/`until`/`limit` is a 400, not a
  silent over-broad result an investigator would trust).

This modifies the `control-plane` capability and touches no core interface.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/controlplane/event_search.go` (new),
  `internal/controlplane/operator_read.go` (mount `/events`).
- Not in scope (stated): full-text / content search inside the payload (the aggregate stores
  raw proto and, by D10, carries no file content to search); a saved-search / query-DSL layer;
  pagination cursors (the cap + time window bound a result set; cursoring is a follow-up if the
  UI needs it).
