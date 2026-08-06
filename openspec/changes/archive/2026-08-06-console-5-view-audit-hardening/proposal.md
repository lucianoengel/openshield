# Close the gaps CONSOLE-5 left in the control it built

## Why

CONSOLE-5 (D482) inverted the default so an operator read is recorded unless somebody writes down why it
is not. Two independent reviews of the shipped commit found six ways the control is still defeatable or
unfalsifiable, and four smaller ways it says something untrue.

The through-line is the one this repo keeps rediscovering: **a mechanism whose input, floor or guard is
missing is a mechanism that reports success while doing nothing.**

- **The audited party can erase the audit.** `OPENSHIELD_VIEW_AUDIT_RETENTION` shipped with no `Bound`,
  while its sibling `OPENSHIELD_FLEET_RETENTION` carries `atLeast(24h)` with the rationale *the purge is
  a SANCTIONED delete path and the ledger's hash chain does not cover it*. That rationale applies here
  verbatim and was not carried over. Config is admin tier with no four-eyes, so an administrator can set
  `0s` plus `OPENSHIELD_RETENTION_INTERVAL=1m` and within a minute `DELETE FROM investigation_views
  WHERE viewed_at < now()` removes everything — including the rows recording that administrator's own
  reads — and then files a tidy compliance event saying so.
- **The five in-handler recorders write `route=''`,** which migration `053` declares means "recorded
  before CONSOLE-5, no route because none was captured". So the five HIGHEST-sensitivity reads — the
  DSAR, a case, an incident timeline, the view audit itself — are indistinguishable from legacy rows,
  and `WHERE route='/cases'` returns nothing forever.
- **The fail-closed branch discards its error.** When it fires, every audited route answers 500 and the
  process's stderr says nothing; `/health` is exempt and still answers 200, so the surface built to say
  whether the process works reports healthy while the console is down.
- **Nothing verifies that the five in-handler routes still record.** The wrapper skips them
  unconditionally because a table says their handler does it. Delete the `RecordView` call from
  `dsarHandler` and the DSAR is silently unaudited with the whole suite green — the exact defect shape
  CONSOLE-5 exists to remove, reintroduced inside the table that replaces it. `/subject` has no test
  asserting it records at all.
- **Nothing enforces that a future mount passes `opRead`.** `enroll_http.go` is ~37 hand-written mounts,
  each of which must remember it. `mux.Handle("/export", s.requireTier(RoleAnalyst, s.exportHandler()))`
  is unaudited and every existing guard passes. CONSOLE-28 (bulk export) is the next ticket.
- **No index on `subject_filter`,** on the table this change makes the largest — a sequential scan
  growing with console traffic, on the route whose purpose is a legally bounded DSAR response.

And four smaller ones: a failed fleet purge `return`s from the tick closure so the notify-dedupe prune
and the view-audit purge never run; `/searches/run` records `name=foo`, a mutable and deletable pointer,
where migration `053` says `query` is *the filter that selected the rows*; the 512-byte bound is asserted
only in terms of itself, so raising it to 1,000,000 keeps every assertion green; a purge that fails for
months is indistinguishable from one never due.

## What Changes

- **`OPENSHIELD_VIEW_AUDIT_RETENTION` gets a floor** with the fleet window's rationale, and the value
  that neuters it joins the refused set in `TestTheValuesThatNeuterTheProductAreRefused`.
- **Every recorded view names its route.** The in-handler recorders record through a route-aware path,
  and `recordViewDetail` refuses an empty route the way it already refuses an empty viewer — so `''`
  goes back to meaning only what migration `053` says it means.
- **The refusal is observable**: the error is logged and counted, the counter is on `/metrics`, and
  `/health` names it as a problem, so the health report cannot say "fine" while the console is refused.
- **Two source-reading guards**, mirroring the CONSOLE-1 route-closure guard: every
  `viewAuditedInHandler` route's handler must contain a recording call, and every operator mount must
  pass `opRead` or be named in an allowlist with its reason. Plus a behavioural test that `/subject`
  records.
- **Migration `054`** indexes `investigation_views (subject_filter)`.
- **The retention tick's purges become independent**, each failure logged with its own target, counted,
  and surfaced on `/health` — a purge failing for months is no longer invisible.
- **`/searches/run` records the RESOLVED query and surface**, not the name that points at it.
- **The recorded query is truncated on an escape boundary**, so a reader that URL-decodes it does not
  get an error, and the bound is asserted against a literal rather than against itself.
- **The subject access report breaks out the subject's own access requests** from other operators'
  reads, and the wrapper's comment stops claiming `subject_filter` holds only genuine subject ids when
  it now holds four namespaces.

## Impact

- Affected specs: `control-plane`, `operator-identity`
- Affected code: `internal/controlplane/view_audit.go`, `views.go`, `dsar.go`, `cases_http.go`,
  `timeline.go`, `savedsearch.go`, `health.go`, `metrics.go`, `controlplane.go`,
  `internal/config/server.go`, `cmd/openshield-server/main.go`,
  `internal/store/postgres/migrations/054_view_audit_subject_index.sql` (new)
- Migration `054` is additive (one index); no row or reader changes meaning.
- `OPENSHIELD_VIEW_AUDIT_RETENTION` below 24h is now REFUSED. A deployment that set one boots with the
  refusal named; nothing silently changes value.
- `test/integration/viewaudit_test.go` moves from a 1m window to 24h, which also removes a latent false
  FAILURE: it inserted its "fresh" row before startup, so a startup slower than 60s aged it out.
