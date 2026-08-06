# Tasks — CONSOLE-5 view-audit hardening

## 1. The audited party cannot erase the audit (MUST FIX 1)

- [x] 1.1 `OPENSHIELD_VIEW_AUDIT_RETENTION` gains `Bound: retentionAtLeast(24*time.Hour, …)` carrying the fleet
      window's rationale — the purge is a sanctioned delete path the hash chain does not cover. The new
      helper exists because `atLeast` exempts `0`, and for a WINDOW zero is not "disabled", it is a
      cutoff of `now()` — the same hole was live on `OPENSHIELD_FLEET_RETENTION` and is fixed with it.
- [x] 1.2 Add the key to `TestTheValuesThatNeuterTheProductAreRefused` with its consequence, and a
      legitimate value to `TestOrdinaryValuesAreStillAccepted`.
- [x] 1.3 `test/integration/viewaudit_test.go` moves to a 24h window with the stale row backdated 48
      hours (also removes the latent false failure from inserting the fresh row before startup).

## 2. Every recorded view names its route (MUST FIX 2)

- [x] 2.1 `recordViewDetail` refuses an empty `Route` with `ErrNoRoute`, as it already refuses an empty
      `Viewer`.
- [x] 2.2 `recordRequestView(r, ViewRecord{…})` derives route and canonical query from the request; the
      in-handler recorders use it (`/views`, `/subject`, `/cases`, `/incidents/timeline`,
      `/searches/run`). `/view` records through `Server.View`, which names the route it serves.
- [x] 2.3 `RecordView` takes a `ViewRecord` rather than four positional strings, so the route is a field a
      call site must name and the compiler finds every caller.
- [x] 2.4 Test: an in-handler-recorded read carries BOTH its route and the subject only its handler
      knows; and a routeless record is refused.

## 3. The refusal is loud (MUST FIX 3)

- [x] 3.1 `Server.ViewAuditFailures` counter; both `viewAudited` failure branches log the cause to
      stderr and increment it.
- [x] 3.2 `openshield_view_audit_failures_total` on `/metrics`.
- [x] 3.3 `HealthReport.ViewAuditFailures` + a `healthProblems` entry, so `/health` cannot report healthy
      while the console's reads are refused.
- [x] 3.4 Test: a failing record makes the health report degraded and names the cause.

## 4. The guards (MUST FIX 4 and 5)

- [x] 4.1 `TestEveryInHandlerAuditedRouteActuallyRecords`: each `viewAuditedInHandler` key's handler
      source contains a recording call (named handler or inline closure).
- [x] 4.2 `TestEveryOperatorMountPassesTheViewAudit`: every `mux.Handle(` on the served mux passes
      `opRead` or is in an allowlist with a reason; a stale allowlist entry fails too.
- [x] 4.3 Behavioural test that `/subject` records — the one in-handler route with no coverage at all.

## 5. The index (MUST FIX 6)

- [x] 5.1 Migration `054_view_audit_subject_index.sql` indexing `investigation_views (subject_filter)`.

## 6. Retention loop (SHOULD FIX 7 and 10)

- [x] 6.1 The three purges in the retention tick run and report independently; a failure no longer
      returns from the closure.
- [x] 6.2 `Server.RetentionPurgeFailures` counter, on `/metrics` and named by `healthProblems`.

## 7. The record says what was read (SHOULD FIX 8 and 9, and the escape-boundary triage)

- [x] 7.1 `/searches/run` joins `viewAuditedInHandler`; the handler resolves the saved search, records
      the resolved surface and filter, then runs it. An unresolvable name is still recorded.
- [x] 7.2 `canonicalViewQuery` truncates on an escape boundary so the stored value stays decodable.
- [x] 7.3 The 512-byte bound is asserted against a literal, not against itself.

## 8. Triage items argued in design.md

- [x] 8.1 DSAR: `ViewsThatWereAccessRequests` breakdown, so the report's own access is visible.
- [x] 8.2 Correct the `subject_filter` comment to name the namespaces actually written there.
- [x] 8.3 Make the mutation count agree across `docs/decisions.md` D482 and this change's record.

## 9. Records

- [x] 9.1 New `D483` row in `docs/decisions.md`; note the hardening on the CONSOLE-5 roadmap entry.
- [x] 9.2 Sync the deltas into `openspec/specs/`, `openspec validate --specs`, archive.
