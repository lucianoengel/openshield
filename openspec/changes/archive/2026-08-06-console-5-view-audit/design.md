# Design — CONSOLE-5 view-audit repair and `investigation_views` retention

## Context

`RecordView` writes `(viewer, subject_filter, event_id, viewed_at)` into `investigation_views`. Four
handlers call it. Since D470 the table is readable at `GET /views`, gated on the privacy officer.

The gap is not that the mechanism is wrong — it is that the mechanism was applied one handler at a time,
by hand, and eleven more read handlers were written afterwards by people who had no reason to know the
invariant existed. That is the failure mode to design out, not just the eight missing rows.

## Decision 1 — one wrapper around the read mux, RECORDING BY DEFAULT

**Chosen:** wrap the whole operator read mux once —
`opRead := s.viewAudited(s.OperatorReadHandler())` — and decide inside the wrapper from `r.URL.Path`
against a package-level exemption table. A path that is in no table is **recorded**.

**Rejected — record inside each handler (the status quo, done eight more times).** It is the same shape
that produced the defect. Eleven handlers each need the identity lookup, the record-then-serve ordering
and the refuse-on-failure branch reproduced correctly, and the twelfth handler — written next month for
`CONSOLE-28`'s export, which is precisely "scroll the fleet and leave nothing" in bulk — silently is not
audited. Nothing anywhere fails when a new route omits it.

**Rejected — a wrapper applied per mount site** (`mux.Handle("/alerts", s.requireTier(RoleAnalyst,
s.audited(opRead)))`). Better, because the decision would sit next to the tier decision, but it has the
same defect one level up: a mount added without the wrapper is unaudited and nothing complains. **The
default is what matters.** Wrapping the mux once makes "audited" the behaviour a new route gets for free
and "not audited" the thing somebody has to write down, with a reason, in a table a reviewer reads.

**Why it can sit outside the handlers at all:** `requireGrant` puts the authenticated principal on the
request context (D470/CONSOLE-1), and the wrapper is mounted *inside* the tier gate. So the identity the
wrapper records is the same one the handler would attribute an act to — there is no second
authentication path, which is the CONSOLE-1 lesson.

**Cost accepted:** the wrapper sees only the URL, so it cannot record a subject the handler learns from
the database (`/cases?id=7` → the case's subject). That is why the four existing in-handler call sites
stay where they are; see Decision 3.

## Decision 2 — GET is a read; a write is attributed by its own act record

The wrapper records `GET` and `HEAD` and nothing else.

Every mutating route on this surface already produces an attributed record of its own: a case note
carries its author, an approval carries both pairs of eyes, an intent carries its publisher, a config
change carries its revision and author. Writing a *view* row for those as well would make
`investigation_views` a partial, second-class duplicate of the act log — and the two would drift, because
one is written before the act and the other after it.

**Residual, stated:** a read implemented as `POST` would not be recorded. There is none today
(`/searches/run` is `GET`), and the exemption table's comment says so, but nothing enforces it. The
honest bound is that this is a convention, checked by review.

## Decision 3 — the exemption table is total over `GET`, and it is two tables, not one

Two maps, deliberately distinct, because "audited elsewhere" and "not audited" are different claims and
collapsing them is how a residual gets lost:

- `viewAuditedInHandler` — `/view`, `/views`, `/subject`, `/cases`, `/incidents/timeline`. Audited, by
  their own handler, which knows a subject id the URL does not carry. The wrapper skips them so a read
  produces one row and not two — a doubled row would make "how often did this operator look" wrong.
- `viewAuditExempt` — path → the reason and the residual. Every entry is a sentence a reviewer can
  disagree with.

**The criterion**, applied to every mounted `GET`:

> A read is evidence-bearing when what it returns is — or narrows to — what the platform holds about a
> person, an entity, or an endpoint's activity. A read of the platform's OWN state (its configuration,
> its health, its roster, its retention record, its approval queue, its saved-search inventory) is not.

### Audited from now on (previously recording nothing)

| Route | Why it is evidence-bearing |
|---|---|
| `/alerts` | the detection queue: pseudonymous subject, risk, host, keyed to people |
| `/search` | the same queue, filterable by subject — the "what do you have on X" question |
| `/events` | the raw fleet aggregate; the broadest evidence read the analyst tier has |
| `/logs` | third-party log CONTENT, ingested from the estate |
| `/searches/run` | executes a stored query over exactly those surfaces — a second door, same rows |
| `/incidents` | correlation output keyed by subject and entity |
| `/incidents/recurrences` | one incident's chain across time |
| `/entities` | the device⋈user graph and per-entity risk — the analyst's pivot onto an asset |

### Exempt, with the residual stated

| Route | Reason | Residual |
|---|---|---|
| `/health` | the control plane's own liveness report; names no subject | none |
| `/logs/fields` | the vocabulary `/logs` accepts — schema, not rows | reveals which vendors feed the store |
| `/compliance/retention` | the record of purges the platform ran | none |
| `/report/response` | MTTA/MTTR aggregates over incidents, no per-subject rows | none |
| `/searches` | the saved-search inventory: names, authors, descriptions | **a saved search's stored query text can itself name a subject, so reading the list shows what colleagues hunt for and leaves no trace.** Bounded by: the author is recorded on the row, and RUNNING one — the read that returns the rows — is audited |
| `/approvals` | the four-eyes queue awaiting a second pair of eyes | it names the intents' target agents. Bounded by: the queue exists to be read by somebody other than the requester, and every resolution is itself recorded |
| `/fleet`, `/fleet/controls`, `/overdue` | fleet operational state: enrolment, silence, break-glass | **a list of which endpoints are dark or not enforcing is a target list for the insider the threat model names, and reading it leaves nothing.** Deliberate: it says nothing about a person, and CONSOLE-8 already argued this tier boundary in the open |
| `/config`, `/config/schema`, `/config/revisions` | the deployment's own configuration | **reading which detections are disabled is reconnaissance, unrecorded.** Bounded by: admin tier only, and every config CHANGE is a recorded revision |

Not on this surface at all, and unchanged: `/enroll` (the fleet credential, not an operator),
`/scim/v2/Users` (the identity provider's own token).

## Decision 4 — the record says what was read: `route` + `query`

Migration `053` adds two columns. `route` is the served path. `query` is the request's query string,
canonicalised (parameters sorted, so two spellings of one search compare equal) and capped at 512 bytes
with an explicit `…(truncated)` marker.

**Rejected — put it in `subject_filter`.** That column means "the subject this read named", and `/subject`
and `/cases` write real subject ids into it. Overloading it with `route=/events&since=…` would silently
break the only join that answers "who looked at me", which Decision 6 depends on.

**Rejected — store nothing but the route.** "Operator X read `/events`" does not distinguish a dashboard
refresh from a targeted search for one named agent, and the boundary being defended is exactly that
distinction.

**Why the cap, and why it is marked:** the query is operator-controlled text written into an audit table
on every request. Uncapped, it is an unbounded write amplification an authenticated insider controls. A
silent truncation would be worse than the cap — a reader would believe a partial record complete — so the
marker is part of the stored value.

## Decision 5 — retention, on the loop that already exists

`OPENSHIELD_VIEW_AUDIT_RETENTION` (dynamic, duration, default `8760h` = one year,
`Sensitivity: LoweringWeakens`), purged by `PurgeViewsOlderThan` inside the same leader-only
`retain.Loop` that purges `fleet_telemetry` and prunes the notify-dedupe ledger, and recorded through
`RecordRetentionEvent` under the target `investigation_views`.

**Why one year, not the fleet window:** the accountability record must outlive the evidence it describes,
or there is nothing left to check a disputed read against. Fleet telemetry defaults to 90 days; the view
of it lasts four times as long.

**Why no `Bound`:** the sibling `OPENSHIELD_NOTIFY_DEDUPE_RETENTION` has none, and a floor here would
make the wiring untestable end-to-end — an integration test proving the purge runs has to set a window it
can outlive within a test's lifetime. The direction of danger is declared (`LoweringWeakens`) and the
weakening surfaces through the existing config-sensitivity machinery, which is the control that actually
fires when somebody lowers it.

**Residual, stated:** the two windows are independent settings. A deployment that raises
`OPENSHIELD_FLEET_RETENTION` past `OPENSHIELD_VIEW_AUDIT_RETENTION` gets evidence that outlives the record
of who read it. Nothing cross-checks them; the description says so.

## Decision 6 — the DSAR path

Two halves, and the second one already exists:

- **The subject's half:** `SubjectReport` gains `views_of_subject` — a count and span of the views whose
  `subject_filter` is this subject. "Who has been looking at me" is the question a data-subject request
  most obviously asks of a table like this, and until now the DSAR did not answer it.
  *Bound:* it covers reads that NAMED the subject. A fleet-wide search that happened to include them is
  recorded as a fleet-wide search, not as a view of them, and the report does not claim otherwise.
- **The operator's half:** `GET /views?viewer=<principal>` returns every row held about that operator, and
  it is the privacy officer's route. That IS the access path; what was missing is that nothing said so,
  and that there was no erasure at the end of it. Decision 5 is the erasure. This change documents the
  route as the access path rather than building a second one — an operator-DSAR endpoint separate from the
  officer's route would be a new authority to design, and the ticket does not need one.

## Decision 7 — a read that cannot be recorded does not happen, on eight more routes

The wrapper refuses with `500` and does not call the handler when the INSERT fails. That is the existing
View invariant (`views.go`, `cases_http.go`, `timeline.go`, `dsar.go`), now uniform.

**Cost accepted, stated plainly:** the console's primary reads now depend on a write succeeding. A
database that can serve reads but not accept this INSERT takes the console's read surface down. That is
the deliberate trade the invariant already makes for `/cases` and `/subject`, and the alternative —
serving evidence while failing to record who took it — is the thing the boundary forbids.

**No principal on the context** is a `500`, not a `401`: past the tier gate it is impossible, so reaching
it means the wrapper was mounted outside `requireGrant`, which is a wiring bug and not an authorization
outcome. `principalFrom` already documents this stance.

## Testing

Mutation-verified throughout (each test names the mutation it was checked against, in a comment).

The ordering claim and the wiring claim need different tests:

- **Package** (`internal/controlplane`, Postgres): the record exists *before* the handler runs — proven by
  an inner handler that queries `investigation_views` and fails if the row is not already there; a failing
  INSERT refuses the read AND the handler never runs; exempt paths write nothing while a neighbouring
  audited path does (the positive half, so the test is not satisfied by a wrapper that records nothing);
  query canonicalisation and truncation; the purge deletes past the cutoff and keeps inside it; the DSAR
  count.
- **Integration** (`test/integration`, build tag `integration`): the wrapper is only real if the SHIPPED
  binary mounts it, and the retention purge's only writer is `cmd/openshield-server`. Both are driven
  against the real server over real mutual TLS: an analyst reads `/alerts`, `/search`, `/events`,
  `/logs`, `/incidents`, `/entities`, `/searches/run` and each leaves a row naming the route; `/health`
  leaves none; and with a one-minute window set through the real config table, the leader's retention loop
  purges the table and records the compliance event.
