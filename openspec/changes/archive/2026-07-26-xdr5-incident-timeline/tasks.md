## 1. Schema and evidence references

- [x] 1.1 Migration `029_incident_timeline.sql`: `incident_alerts (incident_id BIGINT, alert_id BIGINT,
  PRIMARY KEY (incident_id, alert_id))` + an index for the per-incident read; `incidents.domains TEXT[]`;
  `unified_alerts.event_id TEXT` and `.decision_id TEXT` (both nullable). Bump the migration count in
  `postgres_test.go`.
- [x] 1.2 Thread the evidence reference through the alert writers: `RecordUnifiedAlert` takes the
  originating event id + decision id, `projectDecisionAlert` passes the decision's, and the peer-UEBA
  producer passes neither (empty = "server derivation", not missing data).
- [x] 1.3 Test the two producer shapes against real Postgres: a decision-projected alert stores both ids;
  a peer-UEBA alert stores neither and nothing infers one.

## 2. Recording the contributing set

- [x] 2.1 `CorrelateCrossDomain` additionally aggregates the contributing alert ids (`array_agg(id ORDER
  BY detected_at, id)`) onto the returned incident.
- [x] 2.2 `MaterializeCrossDomainIncidents` writes `incident_alerts` with `ON CONFLICT DO NOTHING` and
  stores `domains[]` on the incident row.
- [x] 2.3 Test: a 4-alert / 3-domain correlation records exactly 4 contributions and a 3-entry domain
  list. **Mutation:** drop `ON CONFLICT DO NOTHING` → a second materialization errors or duplicates → the
  test must FAIL. **Mutation:** drop the join write entirely → the count is 0 → FAILs.

## 3. The timeline and its evidence resolution

- [x] 3.1 `TimelineEntry` type: domain, severity, subject, title, detected_at, event/decision reference,
  and a resolution state (`resolved` | `unresolved` | `derived`) with nullable ledger `sequence`/`hash`.
- [x] 3.2 `IncidentTimeline(ctx, incidentID)`: reject a non-cross-domain incident with a typed error
  (`ErrNoTimelineForKind`), return `ErrIncidentNotFound` for an unknown id, else read the contributing
  alerts joined through `incident_alerts` **ordered by `detected_at`, id**.
- [x] 3.3 Evidence resolution: ONE batched query against `audit_entries` for the entries' decision ids.
  A found row → `resolved` + sequence/hash. A reference with no ledger row → `unresolved`, reference
  intact, entry still listed. No reference at all → `derived`. It reads `audit_entries` ONLY — never
  `fleet_telemetry` (D30).
- [x] 3.4 Test evidence resolution on real Postgres: seed an `audit_entries` row for one decision and not
  for another → one entry `resolved` with the right sequence/hash, the other `unresolved` with its
  reference still present, a peer-UEBA entry `derived`. **Mutation:** resolve from `fleet_telemetry`
  instead of `audit_entries` → the unresolved entry becomes "resolved" → FAILs.
- [x] 3.5 Test ordering: alerts inserted in a different order than they were detected come back in
  DETECTION order. **Mutation:** order by `alert_id` → FAILs.

## 4. The endpoint

- [x] 4.1 `GET /incidents/timeline?id=N`: operator-gated, records the view FIRST via the existing
  investigation-views path, then serves; 404 for an unknown id; a clear 409/400 with an explanatory body
  for a `ueba_burst` incident (never an empty list); refuse a request with no identified viewer.
- [x] 4.2 Test the endpoint end to end: 200 + entries for a cross-domain incident, an
  `investigation_views` row naming the operator, 404 for an unknown id, the explicit refusal for a burst
  incident, and 403/401 for a non-operator. **Mutation:** remove the view recording → the privacy
  assertion FAILs.

## 5. The acceptance test

- [x] 5.1 Full path on real Postgres: seed alerts across three domains for one entity through the real
  `RecordUnifiedAlert` path (one of them a decision-projected alert with a seeded ledger entry, one a
  peer-UEBA derivation), materialize the cross-domain incident, then assert the timeline lists ALL
  contributing alerts, cross-domain, time-ordered, each with the correct resolution state.
- [x] 5.2 Assert no timeline field carries content: the entries' titles remain the enum-derived labels and
  no field contains a seeded path/CPF/hostname (D10/D29 boundary, on the timeline's output this time).

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 6.2 Roadmap + decision register: XDR-5 done, XDR-6/XDR-7 named as what remains in the lane; record
  the no-backfill and no-chain-verification limits honestly.
- [x] 6.3 Commit with the `XDR-5` handle, sync the delta specs, archive the change.
