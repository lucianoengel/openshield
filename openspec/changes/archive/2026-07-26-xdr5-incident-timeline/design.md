## Context

State at `HEAD`:

- `CorrelateCrossDomain` (D242) returns per-entity aggregates — counts, domains, first/last seen — and
  discards the identity of the alerts it aggregated. `MaterializeCrossDomainIncidents` writes the incident
  row and nothing else.
- `unified_alerts` (025 + D241) has `entity_id`, `domain`, `subject_id`, `severity`, `title`, `dedup_key`,
  `status`, `detected_at`. The decision projection encodes the decision id inside `dedup_key`
  (`decision:<id>`); there is no column pointing at the originating event or decision.
- `audit_entries` (001, the forward-secure ledger) carries `sequence`, `hash`, `decision_id`, `event_id`.
  It is written by `cmd/openshield-engine` and `cmd/openshield-gateway` via `postgres.Open(dsn, signer)` —
  each with its OWN DSN, which may or may not be the database the control plane reads.
- `investigation_views` + `RecordView(viewer, subjectFilter, eventID)` already exist (T-013/D20), and
  `Server.View` is the established pattern: record the view FIRST, then serve.
- `incidents` since 028 has `kind`, `entity_id`, `domain_count`.

So the timeline needs three things that do not exist: the contributing-alert set, a durable evidence
reference on each alert, and an evidence lookup that is honest about the ledger's trust boundary.

## Goals / Non-Goals

**Goals:**

- One time-ordered, cross-domain view of what an incident is made of.
- A durable evidence reference per alert, and a lookup whose resolved/unresolved/derived states are
  accurate statements about reachability.
- Reading a timeline leaves a view record.

**Non-Goals:**

- Chain verification (the anchor binary owns it), evidence content, the UI, response, entity risk.
- A timeline for burst incidents, or backfilling anything recorded before this change.

## Decisions

### D-1: Store the evidence reference as columns, not by parsing `dedup_key`

`unified_alerts` gains nullable `event_id` and `decision_id`, threaded through `RecordUnifiedAlert`.

The alternative is parsing `decision:<id>` back out of `dedup_key`. Rejected: the dedup key is an
idempotency key whose format is a projection detail — it has already changed once (there is a fallback
form `decision:<event>:<action>`), and a future producer may namespace it differently. Building the
evidence path on it would make a cosmetic change to a key silently break the link from an incident to its
evidence, which is the one link in this feature that must not rot.

Both columns are nullable, and NULL is meaningful rather than missing: a peer-UEBA alert is a server
derivation with no originating endpoint event, and the timeline reports that as its own state.

### D-2: The three resolution states, and why `unresolved` must be visible

`resolved` / `unresolved` / `derived`.

The temptation is a two-state design where anything not found is simply omitted or shown blank. That
would be actively misleading in this system: the aggregate database and the agent's ledger are different
trust domains (D30), so "not found here" is the NORMAL case for a fleet deployment where agents keep their
own ledgers. Omitting those entries would make the timeline look incomplete-but-clean, and an operator
would draw conclusions about what happened from a list that silently dropped rows.

The stronger temptation — and the mutation the tests target — is to "resolve" an entry by handing back the
`fleet_telemetry` row for the same event id. It is right there, it always exists, and it makes the feature
look complete. It is also precisely the D30 confusion the project has spent three review rounds refusing:
the aggregate is a queryable convenience, not evidence. So the resolver reads `audit_entries` only, and a
test asserts that an entry with no ledger row is marked unresolved rather than backfilled from the
aggregate.

### D-3: Report coordinates, claim nothing about integrity

A resolved entry reports `sequence` and `hash`. It does NOT re-walk the chain, and neither the field names
nor the docs describe it as verified. "Here is the entry we point at" is a true and useful statement;
"this entry is intact" would require verification this code does not do, and stating it would be the
overclaim pattern the project's honesty constraints exist to prevent.

Symmetrically, `unresolved` is not evidence of tampering. Both states are documented as reachability
facts.

*Alternative considered:* verify the chain segment during the timeline read. Rejected — it re-implements
the anchor binary's job, and it would put an O(chain) walk behind an operator-facing GET.

### D-4: Record contributions at materialization, from ids the correlator now returns

`CorrelateCrossDomain` additionally aggregates `array_agg(id)`. `MaterializeCrossDomainIncidents` inserts
`(incident_id, alert_id)` rows with `ON CONFLICT DO NOTHING`.

The join must converge, not grow: a re-correlation of an open incident sees the same alerts plus any new
ones, and the incident's evidence set is the union. `ON CONFLICT DO NOTHING` on the composite primary key
is what makes the second run a no-op for already-recorded pairs — without it, a scheduled correlation loop
(SOAR-2) would multiply every incident's evidence set on every tick.

*Alternative:* recompute the contributing set at read time by re-running the rule for the incident's
window. Rejected: the timeline would then change as alerts age out of the window, so an incident's
evidence would silently shrink over time. The join is a record of what the correlation actually saw.

### D-5: Order by `detected_at`, never by id

Alert ids are control-plane insertion order — the order alerts happened to arrive, which for a spooled
agent reconnecting after an outage bears no relation to when the detections occurred. The interleaving
across domains is the whole point of the timeline, so it orders by `detected_at` (id as a stable
tiebreaker only).

### D-6: The endpoint records the view before serving

`GET /incidents/{id}/timeline` follows the existing `Server.View` discipline: record first, then read. An
attempted view is more worth recording than a failed read is worth hiding, and it means the endpoint
cannot be used to enumerate evidence references without leaving a trace (D20/L1).

Routing note: the existing mux uses fixed patterns (`/incidents`, `/incidents/ack`), so the timeline
registers as its own path and parses the id from a query parameter rather than introducing a path-variable
router for one route.

### D-7: A burst incident gets an explicit refusal, not an empty list

A `ueba_burst` incident correlates `peer_alerts` by subject and has no unified-alert join, so it has
nothing to list. Returning `[]` would read as "nothing contributed to this incident", which is false and
exactly the kind of quietly-wrong answer an investigation should not have to second-guess. The response
states the incident kind has no timeline.

## Risks / Trade-offs

- **Alerts and incidents recorded before this change have no references or join rows** → the timeline of a
  pre-existing incident is empty until it is re-materialized, and pre-existing alerts resolve as
  unresolved-with-no-reference. No backfill: inventing an evidence link that was never captured is worse
  than an honestly empty one. Stated in the proposal.
- **An operator may read `unresolved` as "evidence is missing"** → mitigated by naming the state for
  reachability and documenting it in the spec, but the residual risk is real and belongs in the UI's copy
  when PLAT-1 renders it. Flagged rather than solved here.
- **The join grows with alert volume** (one row per alert per incident). Bounded by the correlation
  window and the alerts in it; retention of `unified_alerts` will need to cascade to the join eventually —
  named as a follow-up, not silently ignored.
- **A second evidence lookup per timeline entry.** The resolver batches by querying `audit_entries` for
  the entry's decision ids in one statement rather than per row, so a timeline is two queries regardless
  of length.
- **`domains[]` duplicates what the join could compute.** Accepted: it is what makes an incident list
  legible without a join per row, and it is written from the same aggregate that produced
  `domain_count`, so the two cannot disagree.

## Migration Plan

Migration 029: one new table (`incident_alerts`), `incidents.domains TEXT[]`, and
`unified_alerts.event_id` / `decision_id`. All additive, no rewrite, no backfill. Rollback is the previous
binary, which ignores the new table and columns.

## Open Questions

- Should `unified_alerts` retention cascade to `incident_alerts`? Almost certainly yes; it belongs with
  the retention ticket that owns the purge rules, not here.
- Should the burst rule move onto the unified stream so it gains a timeline too? Deferred — it changes
  shipped behavior and belongs with whichever ticket revisits the two-rule split.
