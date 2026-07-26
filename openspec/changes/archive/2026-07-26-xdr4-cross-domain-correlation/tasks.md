## 1. Schema

- [x] 1.1 Migration `028_incident_cross_domain.sql`: `incidents` gains `kind TEXT NOT NULL DEFAULT
  'ueba_burst'`, `entity_id BIGINT`, `domain_count INTEGER NOT NULL DEFAULT 0`; drop
  `incidents_open_subject_idx` and recreate it kind-scoped; add a partial unique index on `entity_id`
  for `kind='cross_domain'` where `state='open'`. Bump the hardcoded migration count in
  `postgres_test.go` (`TestMigrateIsIdempotent`).
- [x] 1.2 Update `MaterializeIncidents`' `ON CONFLICT` inference to the kind-scoped index and pass
  `kind='ueba_burst'` explicitly. Existing burst tests must pass UNCHANGED — that is the regression gate
  on "the first rule's behavior is untouched".
- [x] 1.3 Test both uniqueness constraints after the reshape: a second open `ueba_burst` incident for one
  subject is refused, a second open `cross_domain` incident for one entity is refused, and a burst
  incident plus a cross-domain incident for the SAME asset coexist (neither upsert overwrites the other).

## 2. The rule, as pure functions

- [x] 2.1 New `internal/controlplane/crossdomain.go`: `CrossDomainRule{Window, MinDomains, MinSeverity,
  Sequence []string}` with safe defaults (window 1h, MinDomains 2), and `CrossDomainIncident{EntityID,
  AlertCount, DomainCount, Severity, Domains, FirstSeen, LastSeen}`.
- [x] 2.2 `matchesSequence(ordered []string, want []string) bool` — ordered SUBSEQUENCE containment
  (interleaved domains allowed, order required, empty `want` matches everything).
- [x] 2.3 Unit-test `matchesSequence` exhaustively: exact match; interleaved match; reversed → NO match;
  missing step → NO match; repeated domains; empty want. **Mutation:** replace it with set containment →
  the reversed case must FAIL.
- [x] 2.4 `escalateSeverity(base string, domainCount int) string` — one bucket per domain beyond the
  first, capped at critical, using the existing four-bucket vocabulary. Unit-test every bucket × domain
  count including the cap and an unrecognized input bucket.
- [x] 2.5 `maxSeverity(severities []string) string` over the contributing alerts' buckets, and a
  `MinSeverity` filter that drops alerts below the floor BEFORE the domain count is taken (so a floor
  cannot be satisfied by alerts that were then excluded).

## 3. Correlation query and materialization

- [x] 3.1 `CorrelateCrossDomain(ctx, rule, now)`: the single aggregate query over `unified_alerts`
  grouped by `entity_id` with `HAVING count(DISTINCT domain) >= MinDomains`, returning the ordered
  `array_agg` of domains and severities; then apply the sequence filter, `maxSeverity` and
  `escalateSeverity` in Go. Parameters bound as data.
- [x] 3.2 `MaterializeCrossDomainIncidents(ctx, rule, now)`: upsert per entity on the new partial index,
  reusing `RETURNING (xmax = 0)` insert-detection and `notifyIncident` so a re-run extends the open
  incident and does NOT re-page.
- [x] 3.3 Test: materialize twice over the same alerts → one incident row, exactly one notification.
  **Mutation:** drop the `xmax` insert-detection → the second run re-pages → the test must FAIL.

## 4. Operator surface

- [x] 4.1 `GET /incidents` gains `rule=cross_domain|ueba_burst` (default `ueba_burst`, response
  unchanged), `min_domains`, and `sequence` (comma-separated). Malformed rule name / non-positive
  `min_domains` / unknown domain in `sequence` → 400, never a silent default (SEC-8).
- [x] 4.2 Test the endpoint: default response identical to the pre-change burst behavior; cross-domain
  selection returns entity-keyed incidents; each malformed parameter is a 400; the surface stays
  operator-gated.

## 5. The acceptance test — real Postgres, real alert path

- [x] 5.1 Seed alerts through the REAL `RecordUnifiedAlert` path (not direct INSERTs): a HIPS exec alert,
  a NIPS DNS alert and a UEBA anomaly alert for ONE entity inside a 10m window → exactly ONE cross-domain
  incident with `domain_count=3`, `entity_id` set, sourced from `unified_alerts`.
- [x] 5.2 The negative half: the same three alerts on THREE different entities → NO cross-domain
  incident.
- [x] 5.3 The device⋈user case: link a device and a user alias, record one domain's alert under the
  device subject and another's under the user subject → they correlate as ONE entity. **Mutation A:**
  group by `subject_id` instead of `entity_id` → the asset splits and the incident never forms → FAILs.
- [x] 5.4 **Mutation B:** remove the `HAVING count(DISTINCT domain) >= $n` condition → a single-domain
  entity raises an incident → the single-domain assertion FAILs.
- [x] 5.5 Severity escalation on real data: three `low` alerts spanning three domains → the stored
  incident severity is two buckets above `low`.

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green locally.
- [x] 6.2 Roadmap + decision register: XDR-4 done, XDR-5 named as next with the `entity_id` it inherits;
  record the ATT&CK-sequence deferral honestly.
- [x] 6.3 Commit with the `XDR-4` handle, sync the delta specs, archive the change.
