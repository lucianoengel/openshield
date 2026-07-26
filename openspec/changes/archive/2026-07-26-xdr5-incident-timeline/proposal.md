## Why

XDR-4 (D242) raises an entity-keyed cross-domain incident that says "4 alerts across 3 domains" — and
nothing records WHICH alerts those were. An operator can see that something correlated and cannot see
what happened, which is the difference between a counter and an investigation. Nothing downstream can
work either: XDR-6 needs to know what it is responding to, and the eventual UI has nothing to render.

There is also no path from an alert back to its evidence. A unified alert keeps no pointer to what
produced it beyond a `dedup_key` string that happens to embed the decision id — a fragile thing to build
an evidence link on.

## What Changes

- **An incident records its contributing alerts.** A new `incident_alerts` join is written at
  materialization, idempotently, so a re-correlation does not duplicate the join.
- **Unified alerts carry evidence references.** `unified_alerts` gains nullable `event_id` and
  `decision_id`, populated by the decision projection (D241). Server-side peer-UEBA alerts leave both
  NULL because they genuinely have no originating endpoint event, and the timeline states that rather
  than rendering a blank field.
- **An incident carries its domain list** (`domains[]`), so the breadth XDR-4 counted is legible without
  re-reading every alert.
- **`IncidentTimeline(id)`** returns the contributing alerts time-ordered ACROSS domains, each with its
  evidence reference and, when resolvable, the ledger coordinates (`audit_entries.sequence` + `hash`) of
  the decision behind it.
- **Evidence resolution is honest about the trust boundary.** The per-agent forward-secure ledger is a
  different trust domain from the fleet aggregate (D30). An entry whose ledger row is not reachable from
  the control plane's database is marked **unresolved**, with its reference intact — never silently
  omitted, and never satisfied by handing back the aggregate row as though it were the evidence.
- **`GET /incidents/{id}/timeline`** — operator-gated, 404 on an unknown id, and it **records the view**
  through the existing investigation-views path. Reading an incident timeline is exactly the "who viewed
  an investigation, not only who acted" requirement, and this endpoint must not become a way to read
  evidence without leaving a record.

## Capabilities

### New Capabilities

- `incident-timeline`: an incident's contributing alerts, time-ordered across domains, each linked to its
  evidence with an explicit resolved/unresolved state — and the view-audit obligation that reading one
  carries.

### Modified Capabilities

- `unified-alerts`: alerts now carry evidence references (`event_id`, `decision_id`) populated by the
  decision projection, with the server-derivation case explicitly having none.
- `cross-domain-correlation`: materialization additionally records the contributing alert set and the
  incident's domain list, idempotently.

## Impact

- **Code:** `internal/controlplane/` — the timeline query and its evidence resolution, the join write in
  the cross-domain materializer, the evidence-reference threading through `RecordUnifiedAlert`, the new
  route, and one migration.
- **Data:** migration 029 adds one join table and three nullable/defaulted columns. No rewrite, no
  backfill: alerts recorded before this change have no evidence reference, and inventing one would be
  fabricating a link that was never captured. Incidents materialized before it have no join rows until
  the next materialization re-records them.
- **Decisions:** depends on **D30** (the aggregate is not the evidentiary ledger — the whole design of
  the resolved/unresolved distinction), **D38** (the timeline is a derived read over authoritative
  records), **D20/L1** (an audit trail of who VIEWED an investigation, not only who acted),
  **D10/D29** (the timeline links to evidence and never inlines matched content), and **D23**
  (pseudonymous subjects throughout). It establishes no new decision.
- No proto change, no new dependency, nothing in the frozen core.

### What this change does NOT claim or cover

- **It does not verify the ledger.** The timeline reports a referenced entry's coordinates
  (`sequence`, `hash`); it does **not** re-walk or re-verify the hash chain, and it must not imply it
  did. Chain verification belongs to the anchor binary. A reported hash means "this is the entry we point
  at", not "we proved this entry is intact".
- **A resolved reference is not proof of evidence integrity**, and an unresolved one is not proof of
  tampering — most often it just means the agent's ledger is not in the database the control plane reads.
  Both states are reported as facts about reachability, nothing more.
- **The timeline links to evidence; it does not inline it.** No matched content, no file bytes, no
  request bodies (D10/D29) — a timeline entry carries closed-vocabulary metadata and references.
- **The timeline is defined for cross-domain incidents only.** A `ueba_burst` incident correlates
  `peer_alerts` by subject and has no unified-alert join, so its timeline request returns an explicit
  "no timeline for this incident kind" rather than an empty list that would read as "nothing
  contributed". Extending the burst rule onto the unified stream is its own change.
- It does **not** act on an incident (XDR-6), aggregate entity risk (XDR-7), or render anything
  (PLAT-1).
- It does **not** retroactively populate evidence references or join rows for data recorded before it
  ships.
