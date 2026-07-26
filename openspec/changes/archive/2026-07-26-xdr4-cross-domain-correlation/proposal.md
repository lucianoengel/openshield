## Why

The `unified_alerts` stream is now fed by every domain (D241), and nothing reads it.
`controlplane.Correlate()` still groups the single-domain UEBA `peer_alerts` table by `subject_id`
string — so the platform has a multi-domain alert stream and a single-domain correlator, and they have
never been connected. XDR-4 is where they join, and until they do, "cross-domain XDR" is a table, not a
capability: an attack that shows up as an exec on the endpoint, a DNS lookup at the gateway, and an
identity anomaly in analytics is still three unrelated alerts.

## What Changes

- **A second, additive correlation rule over `unified_alerts`, keyed by the graph ENTITY.** Alerts group
  by `entity_id`, never by a subject string, so a device⋈user asset correlates as one thing — the entity
  join is the whole point of the ticket, not an implementation detail.
- **A multi-domain window rule:** an entity with alerts from at least N distinct domains inside the
  window raises one cross-domain incident carrying `domain_count`.
- **An ordered-sequence rule:** an operator-specified domain sequence (e.g. `ueba→hips→nips`) matched as
  an ordered SUBSEQUENCE of the entity's alerts within the window. Out-of-order or incomplete does not
  match — a set-containment check would call a reversed sequence a hit, which is a different (and much
  weaker) claim.
- **Severity boosted per additional domain:** base is the entity's highest alert severity, raised one
  bucket per distinct domain beyond the first, capped at critical. It reuses the existing four-bucket
  vocabulary (ADR-10) rather than inventing a second scale.
- **Cross-domain incidents materialize and page exactly once**, reusing the existing
  `RETURNING (xmax = 0)` insert-detection so SOAR-1's "a re-correlated burst must not re-page" property
  holds identically for the new rule.
- **`incidents` gains `kind`, `entity_id`, `domain_count`** (migration 028). `kind` defaults to
  `ueba_burst`, so every existing row and the existing rule behave exactly as before; the partial unique
  index that enforces one open incident per subject becomes kind-scoped, and a new partial unique on
  `entity_id` is the cross-domain upsert's conflict target.
- **`GET /incidents` gains opt-in rule selection** (`rule=cross_domain&min_domains=N&sequence=…`). The
  default response is unchanged. A malformed parameter is a 400, never a silent fall back to a default
  that returns a wider result set looking authoritative (SEC-8).

## Capabilities

### New Capabilities

- `cross-domain-correlation`: correlating the entity-keyed multi-domain alert stream into incidents —
  the multi-domain window rule, the ordered-sequence rule, per-domain severity escalation, and
  materialization that pages once.

### Modified Capabilities

- `control-plane`: the `GET /incidents` contract gains opt-in rule selection with fail-loud parameter
  validation; the default remains the existing burst rule.

## Impact

- **Code:** `internal/controlplane/` — a new cross-domain correlation unit, the materializer, the
  handler's rule selection, and one migration. `Correlate()`, `MaterializeIncidents()`, `peer_alerts`
  and the UEBA burst rule are **untouched**: this is a second rule beside the first, not a replacement,
  so nothing that works today changes behavior.
- **Data:** migration 028 alters `incidents` additively (three nullable/defaulted columns) and reshapes
  two partial indexes. No data rewrite, no table drop, no change to `unified_alerts` or `peer_alerts`.
- **Decisions:** depends on **D38** (an incident is a derived index over the authoritative alert
  records), **D23** (correlation reads pseudonymous subjects and content-free domain labels only),
  **D54** (the fleet derivation is deliberately separate from received telemetry), and **ADR-10** (one
  severity vocabulary). It consumes the entity graph from **D203/D241**. It establishes no new decision.
- **No** proto change, no new dependency, and nothing in the frozen core: correlation is a read-side
  derivation in the control plane.

### What this change does NOT claim or cover

- **The sequence vocabulary is DOMAINS, not MITRE ATT&CK techniques.** The roadmap suggested reusing the
  SIEM-7 ATT&CK tags, and that is not currently possible: `internal/attack` techniques are computed in
  `internal/policy/mapping.go` as Rego policy *input* and are never persisted on an alert — the Decision
  contract does not carry them. Technique-level sequences need a contract change, so they are deferred
  and named rather than faked with a weaker signal wearing the ATT&CK label.
- It does **not** build the incident timeline, the `incident_alerts` join, the `domains[]` array, or
  `GET /incidents/{id}/timeline` — that is XDR-5, which builds on the `entity_id` this ticket adds.
- It does **not** act on an incident (XDR-6/SOAR-7), and it does **not** suppress alert storms: a noisy
  entity produces one incident whose counts grow, but nothing rate-limits the alerts feeding it.
- It does **not** retro-correlate. Only alerts inside the window are considered; alerts that predate it
  are never pulled into an incident, and no backfill of historic alerts is attempted.
- The domain label it correlates on is the coarse grouping hint D241 established, not an authoritative
  taxonomy. A `domain_count` of 3 means "three of OpenShield's domain labels", which is what an operator
  tunes `min_domains` against — it is not a claim about three distinct attacker techniques.
- It makes **no** claim that a correlated incident is a true positive. Correlation raises confidence; it
  does not establish certainty (D4), and the severity boost is a triage-ordering heuristic, not evidence.
