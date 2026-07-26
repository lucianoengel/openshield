## Context

Current state, verified at `HEAD`:

- `internal/controlplane/correlate.go` — `Correlate(rule, now)` groups `peer_alerts` by `subject_id`,
  `HAVING count(*) >= MinAlerts AND count(DISTINCT NULLIF(agent_id,'')) >= MinHosts`, severity from
  `max(risk_score)`. It never touches `unified_alerts`.
- `internal/controlplane/incidents.go` — `MaterializeIncidents` upserts one open incident per subject
  (`ON CONFLICT (subject_id) WHERE state = 'open'`) and pages only when `RETURNING (xmax = 0)` says the
  row was genuinely inserted (SOAR-1, D220).
- Migration `018_incidents.sql` — `incidents` is subject-keyed with
  `CREATE UNIQUE INDEX incidents_open_subject_idx ON incidents (subject_id) WHERE state = 'open'`.
- `unified_alerts` (025) — `entity_id`, `domain`, `subject_id`, `severity`, `title`, `dedup_key`,
  `status`, `detected_at`, now written by every domain (D241).

So the pieces are: a filled multi-domain stream, a single-domain correlator, and an incidents table that
cannot express an entity-keyed incident. This change adds the second rule and the columns it needs, and
touches none of the first rule's behavior.

## Goals / Non-Goals

**Goals:**

- Correlate `unified_alerts` by graph entity into cross-domain incidents, with a multi-domain window rule
  and an ordered-sequence rule.
- Preserve the existing burst rule bit-for-bit, including SOAR-1's page-once property, and preserve the
  default `GET /incidents` response.
- Keep the rule logic in pure Go so every branch is unit-testable without a database.

**Non-Goals:**

- The incident timeline, `incident_alerts`, `domains[]`, `GET /incidents/{id}/timeline` (XDR-5).
- Acting on an incident (XDR-6/SOAR-7); alert-storm suppression; retro-correlation.
- ATT&CK-technique sequences — see D-2.

## Decisions

### D-1: One `incidents` table with a `kind` discriminator, not a second table

Migration 028 adds `kind TEXT NOT NULL DEFAULT 'ueba_burst'`, `entity_id BIGINT`, and
`domain_count INTEGER NOT NULL DEFAULT 0`; replaces `incidents_open_subject_idx` with a kind-scoped
partial unique index; and adds a partial unique index on `entity_id` for the cross-domain kind.

*Why the index reshape is mandatory rather than cosmetic:* a cross-domain incident needs a representative
`subject_id` for display, and the existing index enforces one open incident per subject regardless of
kind. Leaving it in place would make a burst incident and a cross-domain incident for the same asset
collide — the second upsert would silently overwrite the first, and an operator would lose an incident
without a trace. Scoping the index by kind is what lets the two rules coexist.

*Alternatives:*

- **A separate `cross_domain_incidents` table.** Rejected: XDR-5's timeline, XDR-6's response, SOAR's
  playbooks and the ack/case-link surfaces would each need to handle two incident types, doubling every
  downstream join for a distinction that is one column.
- **Re-key the whole table on `entity_id` and migrate the burst rule to it.** Rejected for this ticket:
  it changes the behavior of a shipped, tested rule (and SOAR-1's paging) for no benefit to XDR-4. If the
  burst rule should become entity-keyed, that is its own change with its own migration and tests.
- **Add `entity_id` NOT NULL.** Rejected: existing rows have no entity, and a backfill would invent one.
  Nullable, with the cross-domain rule always setting it, is the honest shape.

### D-2: The sequence vocabulary is DOMAINS, not ATT&CK techniques

The roadmap proposed reusing the SIEM-7 ATT&CK tags as the sequence vocabulary. That is not currently
possible: `internal/attack.Techniques()` is called from `internal/policy/mapping.go` to build Rego policy
*input*, and the techniques are never persisted — `unified_alerts` has no technique column and the
`Decision` contract does not carry one. Getting them onto an alert means either widening `Decision` (the
most security-sensitive contract in the system) or re-deriving techniques server-side from data the
control plane does not have.

So this ticket sequences on the domain label, and says so. The alternative — labelling a
domain-sequence rule "ATT&CK correlation" — would be exactly the kind of overclaim this project's review
rounds exist to catch. Persisting technique tags is a legitimate follow-up ticket, named in the proposal.

### D-3: Aggregate in SQL, decide in Go

One query per correlation run:

```sql
SELECT entity_id, count(*), count(DISTINCT domain), min(detected_at), max(detected_at),
       array_agg(domain   ORDER BY detected_at, id),
       array_agg(severity ORDER BY detected_at, id)
  FROM unified_alerts
 WHERE detected_at >= $1
 GROUP BY entity_id
HAVING count(DISTINCT domain) >= $2
```

The ordered `array_agg`s carry everything the sequence check and the severity computation need, so both
run as pure functions over a `[]string` — unit-testable exhaustively, with no database and no fixtures.

*Alternatives:*

- **Express the sequence rule in SQL** (window functions / lateral joins over ordered alerts). Rejected:
  the ordering semantics are the subtle part of this ticket, and a subsequence match is far easier to get
  right and to prove in Go than in a correlated subquery. SQL does the set-based work it is good at
  (grouping, counting distinct); Go does the logic.
- **Fetch all alerts and group in Go.** Rejected: it moves an unbounded result set into memory to
  re-implement `GROUP BY`.

The `HAVING` prefilter stays in SQL deliberately: it is the cheap condition that keeps the aggregate rows
proportional to interesting entities rather than to all entities.

### D-4: Severity = max contributing bucket, +1 bucket per extra domain, capped

Breadth is the signal this rule exists to surface: three domains lighting up on one asset is
qualitatively different from three alerts in one domain, and an operator sorting by severity should see
it. The escalation reuses the four-bucket ladder (ADR-10) so there is one vocabulary in the system.

Stated plainly in the spec: this is triage ORDERING, not evidence. A correlated incident is not a
confirmed true positive — confidence, not certainty (D4).

*Alternative considered:* a numeric cross-domain risk score. Rejected — it would be a second scale with
no calibration behind it, and the four buckets exist precisely because a false-precision number is worse
than a coarse bucket an analyst can hold in their head.

### D-5: Rule selection on the existing endpoint, default unchanged

`GET /incidents` takes `rule=cross_domain` plus `min_domains` and `sequence`. No selector means the burst
rule, byte-identical to today. Unknown rule names and malformed thresholds are 400s, following the SEC-8
discipline already applied to `window`/`min_risk`/`min_alerts`: a silently-defaulted bad parameter
returns a wider set that looks authoritative.

*Alternative:* a new `/incidents/cross-domain` endpoint. Rejected — it would fork the operator surface
(and later the ack/case-link paths) over what is one rule parameter.

## Risks / Trade-offs

- **The index reshape is the risky part of the migration.** Dropping and recreating a unique index on a
  live table means a window where uniqueness is unenforced. Mitigated by doing it in one transaction (the
  migration runner already wraps each file) and by a test that asserts both kinds' uniqueness afterward:
  a second open incident of the same kind for the same key must be rejected.
- **`domain_count` is only as meaningful as the domain labels.** D241's labels are coarse (ZT denials
  land under `nips`), so `min_domains=3` is an operator-tuned threshold over OpenShield's labels, not a
  claim about three attacker techniques. Stated in the proposal and the spec.
- **Severity inflation.** Any entity with three noisy domains reaches a high bucket. Accepted for this
  increment: breadth is the signal, and the tuning knob is `min_domains`. If it proves noisy in practice,
  the fix is per-domain weighting or storm suppression — a later ticket with evidence, not a guess now.
- **Window boundary effects.** An attack that straddles the window is correlated as whatever falls
  inside it, and no retro-correlation reaches back. This is inherent to a windowed rule; the honest
  mitigation is that the window is an operator parameter, and the limitation is documented rather than
  hidden behind a default that looks total.
- **Two rules can both fire on one asset**, producing two incidents (one per kind). That is intended —
  they answer different questions — but it means an operator's incident list can contain two rows for one
  asset. XDR-5's timeline is where they become legible together.

## Migration Plan

Migration 028 is additive plus an index reshape, applied by the existing runner; no data rewrite and no
backfill (existing rows keep `kind='ueba_burst'`, `entity_id` NULL, `domain_count=0`, which is exactly
what they are). Rollback is the previous control-plane binary: the added columns are ignored by it, and
the reshaped indexes remain valid for the old code's `ON CONFLICT (subject_id) WHERE state='open'` only
if that inference still matches — so a rollback that must also revert the index requires the down-step to
be run manually. Called out here rather than assumed.

## Open Questions

- Should the burst rule eventually become entity-keyed too, collapsing to one rule with a domain
  threshold of one? Deferred — it changes shipped behavior and belongs with XDR-5's view of incidents.
- Should technique tags be persisted on `unified_alerts` (enabling real ATT&CK sequences)? Needs a
  decision about widening the `Decision` contract; deliberately not settled here.
