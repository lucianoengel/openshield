# Design — hardening the CONSOLE-5 view audit

## Context

D482 shipped the wrapper, the schema and the retention window. Two independent reviews of commit
`ef31b21` then asked the question the ticket itself asks of every other control: *what makes this
falsifiable, and who can turn it off?* Six answers were unsatisfactory.

Every item below is one of two shapes:

1. **The mechanism has no floor, so the party it constrains can remove it** (the retention bound).
2. **The mechanism has no guard, so removing it leaves the suite green** (the in-handler table, the
   mount list, the 512-byte bound asserted against itself).

Both are shapes this repo has a scar for. The first is R34's "the mechanism was right, its input was
worthless". The second is the CONSOLE-1 route-closure guard's reason for existing.

## Decision 1 — the retention window gets a FLOOR, not a warning

**Chosen:** `Bound: atLeast(24*time.Hour, …)` on `OPENSHIELD_VIEW_AUDIT_RETENTION`, carrying the fleet
window's rationale, which applies here word for word: the purge is a sanctioned delete path and the
ledger's hash chain does not cover it, so shortening the window destroys evidence without leaving the
tamper trace that deleting rows directly would.

The attack it closes is specific. `/config` is admin tier with no four-eyes and no TTL (`viewAuditExempt`
says as much, and calls the residual real). An administrator sets `OPENSHIELD_VIEW_AUDIT_RETENTION=0s`
and `OPENSHIELD_RETENTION_INTERVAL=1m`; within a minute the leader runs
`DELETE FROM investigation_views WHERE viewed_at < now()`, which is every row, including the rows
recording that administrator's own reads. The purge then files a retention compliance event, so the
erasure looks like policy.

**Why 24h and not something longer.** The floor's job is to make "erase the audit" not expressible as a
retention setting; it is not to pick a privacy policy for the operator. 24h is the same floor the fleet
aggregate carries, and the same argument produced it. A deployment wanting a genuinely short window can
have one day; nobody legitimately wants zero.

**Rejected — `Sensitivity: LoweringWeakens` alone**, which is what shipped. It computes the direction of
the change and records it in the config revision, which is real and worth having. It does not *refuse*
anything. The whole point of D482's threat model is an insider who holds the credential; a record that
they weakened it, written into a table they can then purge, is not a control.

**Rejected — four-eyes on this one key.** The four-eyes machinery is per-intent, not per-config-field,
and inventing a field-level approval path for one key is a new authority to design and test. The floor
is the cheap half and it removes the destructive end of the range outright.

**Consequence for the integration test:** it configured `1m`, below the new floor. It moves to `24h`
with the stale row backdated 48 hours. That still proves the operator's value was READ rather than a
constant — a 48-hour-old row survives the 8760h default and dies under 24h — and it removes a latent
false FAILURE the reviewers also flagged: the "fresh" row was inserted before server startup under a 1m
window, so a startup slower than 60 seconds aged it out and failed the honesty half spuriously.

## Decision 2 — `route` is required, so `''` keeps meaning what the migration says

Migration `053` states: an empty `route` means the view was recorded before CONSOLE-5, "no route because
none was captured". The five in-handler recorders write `''`, so the highest-sensitivity reads in the
product are indistinguishable from legacy rows and `WHERE route='/cases'` is empty forever.

**Chosen: both halves of the reviewers' "and/or".**

- A route-aware recorder, `recordHandlerView(r, viewer, subjectFilter, eventID)`, derives `Route` from
  `r.URL.Path` and `Query` from the same `canonicalViewQuery` the wrapper uses. The five handlers call
  it. They keep their subject — which is the whole reason they record in the handler — and gain the
  route they always had available.
- `recordViewDetail` refuses an empty `Route` exactly as it refuses an empty `Viewer`, with
  `ErrNoRoute`. Recording without a route is now unrepresentable rather than merely discouraged.

**Why both.** The first fixes today's five. The second is what makes the sixth — written next month —
fail loudly instead of writing a legacy-looking row. That is the same argument the wrapper itself makes,
one layer down.

**Consequence for `RecordView`.** The exported four-argument helper cannot satisfy the new rule, because
it has no request. Its only production callers were the five handlers, and they now use the route-aware
path. It is kept for the one caller that genuinely has no route — `Server.View`, the library-level
"serve an investigation and record it" call — which passes the route its own HTTP handler serves. So
`RecordView` grows a route parameter rather than being deleted: a helper that can only produce refused
records would be a trap.

**Rejected — backfill the existing `''` rows.** There is no information to backfill from. The rows are
genuinely routeless; the migration already says so, and now that statement is true again.

## Decision 3 — a refused read is LOUD

`viewAudited`'s two failure branches wrote a 500 and returned, discarding the error. The combination
that makes this bad is specific: `/health` is exempt, so it keeps answering 200 with `degraded: false`
while every other operator route is refused. The one surface built to tell an operator whether the
process works reports that it works.

**Chosen:** a `ViewAuditFailures` counter on `Server`, incremented in both branches, each with its own
stderr line naming what happened and the wrapped error; the counter on `/metrics`; and a `HealthReport`
field with a `healthProblems` entry that says what the operator is seeing and what it means.

The two branches share one counter and carry different messages, deliberately. As a *number* they are
one condition — audited reads are being refused, and the console is down — which is what a health tile
needs. As a *log line* they send someone to different places: a database that cannot accept the INSERT,
versus a wrapper mounted outside the tier gate.

**Pattern borrowed from `RecordRetentionEvent`** (`retention_report.go:35`), which already does count +
stderr for the same class of "the thing happened, the evidence of it did not".

## Decision 4 — two source-reading guards, because the tables are now load-bearing

`viewAudited` skips five paths unconditionally on the strength of a comment. Delete the `RecordView`
call from `dsarHandler` and the DSAR is unaudited with the whole suite green. That is the defect D482
exists to remove, reproduced inside the table that replaced it.

**Chosen:** guards over the source, mirroring `operator_route_closure_test.go`, which already reads the
mount list out of `enroll_http.go` and is the accepted precedent in this package.

- `TestEveryInHandlerAuditedRouteActuallyRecords`: for each `viewAuditedInHandler` key, find the handler
  the route is registered with and assert its body contains a recording call. Registration is either
  `mux.HandleFunc("/x", s.name)` — follow to `func (s *Server) name(` — or an inline
  `mux.HandleFunc("/x", func(…)` — take the literal body. Both forms exist (`/view` is inline inside
  `ViewHandler`).
- `TestEveryOperatorMountPassesTheViewAudit`: every `mux.Handle(` on the served TLS mux either passes
  `opRead` or is named in an allowlist with a reason of real length. `/enroll` (agent role, not an
  operator read), `/view` (audited in its own handler, mounted with its own handler) and the two SCIM
  mounts (token-authenticated, not an operator credential) are the allowlist. A stale allowlist entry
  fails too, for the reason `TestEveryViewAuditDecisionNamesARealRoute` already gives.

**Rejected — behavioural tests alone for the five.** They are better evidence and they do not scale to
the mount list, which is the half CONSOLE-28 walks into. `/subject` gets one anyway, because it had
none, and because a source guard proves a call is written, not that it runs before the response.

**Rejected — making the route set data so the divergence is unrepresentable.** Same answer the
route-closure guard gave and for the same reason: restructuring 37 security-gated mounts risks landing
one at the wrong TIER, which is worse than the drift being guarded against.

**Honest limit, stated in the guard:** a source scan proves a *call is present*, not that it executes on
every path. A handler could record inside an `if` nobody enters. The guard catches deletion, which is
the failure the reviewers demonstrated; the behavioural tests catch the rest for the routes that have
them.

## Decision 5 — the query is the filter that selected the rows, including for a saved search

`/searches/run?name=team-hunt` is audited by the wrapper, so the recorded query is `name=team-hunt`. The
name is a mutable, deletable pointer: `SaveSearch` is upsert-on-name and `/searches/delete` is a hard
delete, both at responder tier. An audit row saying "they ran `team-hunt`" can be made to mean anything,
or nothing, by a responder afterwards.

**Chosen:** `/searches/run` joins `viewAuditedInHandler`. The handler resolves the name first, records
`route=/searches/run` with a query carrying the name, the surface and the RESOLVED filter, then runs it.

Resolving before recording is not a violation of record-then-serve: the saved-search row is not the
evidence. The evidence is the alerts, events or logs the filter selects, and nothing is read from those
stores until after the record is written. A name that does not resolve is still recorded, with the
reason — an attempted read is worth recording whether or not it found anything, which is the rule the
integration test already asserts for 404s.

## Decision 6 — the index, the independent purges, and the truncation boundary

**`054_view_audit_subject_index.sql`** indexes `investigation_views (subject_filter)`. `007` indexed
`viewer` and `event_id`; `053` added `viewed_at`; the DSAR's `WHERE subject_filter = $1` was the one
predicate with no index, on the table D482 makes the largest, on the route with a statutory clock.
A new migration rather than amending `053`, which has shipped and been applied.

**The retention tick's purges become independent.** A failed fleet purge `return`ed from the closure, so
the notify-dedupe prune and the view-audit purge never ran and the only stderr line named the fleet
purge. Each purge now runs and reports on its own. A failure increments `RetentionPurgeFailures` and is
named on `/health`.

**Rejected — writing a failure row into `retention_events`.** That table means "data past the window WAS
deleted"; a row that means the opposite makes every existing reader of the compliance report wrong,
including the one the integration suite asserts against. The counter plus the health problem gives the
auditor the same distinction — a purge failing for months versus one never due — without corrupting the
record's meaning.

**`canonicalViewQuery` truncates on an escape boundary.** `q[:maxViewQueryLen]` can cut inside a `%XX`
escape, and the value is produced by `url.QueryEscape`, so a reader that URL-decodes gets an error
instead of a partial query. Backing off the 1–2 trailing bytes of an incomplete escape costs two lines
and makes the stored value always decodable. The marker still says it was truncated, so nothing reads
as complete.

## Decision 7 — the DSAR counts the subject's own requests separately

`ViewsOfSubject` counts every row with `subject_filter = <subject>`, and `subjectHandler` records its
own access with `event_id='dsar'` BEFORE compiling the report. So the count includes the request being
answered: ask twice and the number grows by one each time, with no way for the subject to tell their own
requests from an analyst's.

**Chosen:** keep the total and add the breakdown —
`count(*) FILTER (WHERE event_id = 'dsar')` — as `OfWhichSubjectAccessRequests`.

**Rejected — excluding DSAR rows from the count.** A subject access request IS an operator reading the
subject's file, and dropping it would hide a real access. The subject asked "who looked at me"; the
answer is "seven times, of which three were your own requests", not a number quietly adjusted to be
less confusing.

## Decision 8 — say what `subject_filter` actually holds

The wrapper's comment claims only a genuine subject id belongs in `subject_filter`. Four namespaces are
written there today: subject ids (`/subject`, `/cases`, `/search?subject=`), `incident:<id>`
(`/incidents/timeline`), and operator principals (`/views?viewer=`). They do not collide — subject ids
are pseudonyms, and neither `incident:` nor `cert:`/`oidc:` is one — so the DSAR join is sound. The
comment is corrected to say that, because a comment asserting a narrower invariant than the code holds
is how the next person writes a fifth namespace that does collide.
