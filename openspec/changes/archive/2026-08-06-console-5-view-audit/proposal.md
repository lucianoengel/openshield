# Repair the view audit before a console makes reading free

## Why

`docs/threat-model.md` bounds the malicious insider holding an operator role with one sentence: **"Who
LOOKED is recorded, not only who acted, and the record is written BEFORE the evidence is returned."**

That sentence is true of four routes and false of the console's primary ones. `RecordView` has four call
sites — `views.go` (`/view`, `/views`), `timeline.go` (`/incidents/timeline`), `dsar.go` (`/subject`),
`cases_http.go` (`/cases`). `/alerts`, `/search`, `/events`, `/logs`, `/searches/run`, `/incidents`,
`/incidents/recurrences` and `/entities` record **nothing**. Those are exactly the routes a console
renders: an operator with an analyst grant can search the fleet aggregate for a named agent, read the raw
external-log store, and page the entity graph, and the accountability table stays empty.

Today that gap is bounded by ergonomics — it takes a deliberate `curl`. `PLAT-1` removes that bound. A
console turns "scroll the fleet and leave nothing" from an exercise into the default interaction, so
shipping the UI on top of this makes the documented boundary weaker than it was before the UI existed.

Two further defects sit in the same place:

- **`investigation_views` records the read but not what was read.** The schema is
  `(viewer, subject_filter, event_id)`. Nothing carries the ROUTE or the FILTER, so a record of a
  fleet-wide search says an operator looked, without saying at what. For the four existing call sites the
  route was implied by the shape of the arguments; across eight more it is not recoverable at all.
- **The table has no TTL, no purge and no DSAR path** (migration `007`), while storing raw,
  non-pseudonymised operator identities. Every other subject-adjacent store in this product is bounded:
  `fleet_telemetry` and `peer_alerts` are purged on a timer under `OPENSHIELD_FLEET_RETENTION`, the
  notify-dedupe ledger under its own window, and each purge is recorded as a compliance event. The
  accountability table is the one that grows forever — and a console makes it the largest table in the
  database. "We keep a permanent, unbounded, personally-identifying record of everything every employee
  looked at" is not a privacy posture this product can defend.

## What Changes

- **Recording moves to the mount site.** A per-route wrapper records the view BEFORE the handler runs, so
  a route is audited by the line that mounts it rather than by whether its handler author remembered.
  The decision is made once per route, in one table, in the file that already carries the tier decision.
- **A per-route decision is recorded for EVERY mounted route** — audited or not, with the reason. Eight
  routes become audited; the rest are named as deliberate exclusions with their residual stated.
- **The record says what was read.** `investigation_views` gains `route` and `query`: the path served and
  the canonicalised, length-bounded query that selected the rows.
- **`investigation_views` gets a retention window and a purge**, `OPENSHIELD_VIEW_AUDIT_RETENTION`, run by
  the same leader-only retention loop that purges telemetry and recorded as a compliance event under the
  target `investigation_views` — so the erasure is provable to the same auditor as every other purge.
- **The DSAR reports it.** A subject's access report counts the views that named them, and
  `GET /views?viewer=` is documented as the operator's own access path to what is held about them.

## Impact

- Affected specs: `control-plane`, `operator-identity`
- Affected code: `internal/controlplane/views.go`, `view_audit.go` (new), `enroll_http.go`, `dsar.go`,
  `internal/config/server.go`, `cmd/openshield-server/main.go`,
  `internal/store/postgres/migrations/053_view_audit_retention.sql` (new)
- Migration `053` is additive (two columns with defaults, one index); no existing row or reader changes
  meaning.
- Every audited route gains one INSERT per request. A read that cannot be recorded is refused with 500 —
  the existing View invariant, now applied to eight more routes.
