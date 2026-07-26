## Why

`unified_alerts` (XDR-2 increment 1) shipped with exactly **one** producer: server-side peer-UEBA
(`controlplane/signed.go` → `recordDeviceUnifiedAlert`). Every other detection domain — DLP verdicts,
HIPS behavioral detections, DNS/SMTP/network classify hits, ZT access denials — still ends at its own
domain record and never reaches the normalized, entity-keyed stream. A "cross-domain" correlation table
fed by a single domain cannot correlate anything, so XDR-4 (the next MVP ticket) has no input. This is
the hard precedence in Lane A: wire the producers before writing correlation rules over them.

## What Changes

- **A verified, non-ALLOW `Decision` is projected into `unified_alerts` at ingest.** The control plane's
  signed-telemetry path (`handleSigned`) already receives every domain's `Decision` from every enrolled
  producer (endpoint engine → DLP/HIPS; gateway → network/DNS/SMTP and the ZT access proxy). A decision
  whose action is anything other than `ACTION_ALLOW`/`ACTION_UNSPECIFIED` becomes one normalized alert.
- **The originating event supplies the entity key and the domain.** A `Decision` carries neither a
  subject nor an event kind, so the projection joins back to the already-persisted `event` row by
  `event_id` and reads `Subject.PseudonymousId` (the entity key) and `EventKind` (the domain). Domain
  mapping: file/USB → `dlp`; process-exec, ransomware-suspected, memory-injection-suspected, file-deleted
  → `hips`; network-flow, http-request, dns-query, smtp-message → `nips`.
- **Severity is derived from the closed Action enum + the decision's confidence**, reusing the existing
  `Severity()` bucket mapping as the single source of truth; enforcement actions (BLOCK, DENY_EXEC,
  KILL_PROCESS, QUARANTINE_LOCAL, ENCRYPT_LOCAL, REDIRECT) take a `high` floor, `ALERT` keeps the
  confidence-derived bucket. The alert **title is built from closed enum names only** — never the policy
  `reason` string, never a path, host, or any classifier detail (D10/D29).
- **Entity keying prefers an existing alias of ANY kind before minting a device alias.** The gateway's
  access-proxy subject is a *user* identity, and the proxy already links device⋈user in the graph. Under
  today's device-only resolution a ZT denial would create a second, unlinked `device` alias holding a
  user value and fork onto a separate entity — the one thing that breaks cross-domain grouping. The
  entity store gains a value-scoped, kind-agnostic **lookup** (no creation); unified-alert keying uses it
  first and falls back to the existing resolve-or-create behavior.
- **Observability:** a counter for decisions that could not be projected (no persisted originating event,
  unresolvable subject), so a silently unfed correlation stream is detectable.

No proto change, no new dependency, and no schema or data change — one additive index-only
migration (a value-only index on `entity_aliases`, which the kind-agnostic lookup needs because the
alias primary key is `(kind, value)`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `unified-alerts`: adds the requirements that make it a real multi-domain stream — every domain's
  enforcement/alert decision is projected at verified ingest, the domain is derived from the originating
  event kind, severity is derived from the closed action set, projection is best-effort and counted, and
  an ALLOW decision is never an alert.
- `entity-model`: adds a kind-agnostic **lookup by alias value** (resolve-existing, never create), the
  primitive that lets a detection key onto an entity a *different* domain already named — the device⋈user
  case.

## Impact

- **Code:** `internal/controlplane/` (a new decision→alert projection unit, the ingest hook in
  `handleSigned`, entity keying inside `RecordUnifiedAlert`, one new counter); `internal/xdr/store.go`
  (the lookup). No producer binary changes — the endpoint engine and gateway already publish signed
  decisions; this is a **read-side projection in the control plane**, so nothing in the frozen core, the
  Event/Decision contracts, or the enforcement path moves.
- **Decisions:** depends on **D10/D29** (only type/metadata crosses the boundary — the alert title and
  domain are derived from closed enums, never content), **D14** (the closed, typed action set is what
  makes an action→severity mapping total and safe), **D38** (a derived index is best-effort: a projection
  failure is counted, never rolls back or changes the ingest outcome), **D44** (only VERIFIED telemetry is
  evidence — the unverified legacy path does not project), and **D23** (the entity key is the pseudonymous
  subject, never a raw identity). It establishes no new decision.
- **Data:** writes only to the existing `unified_alerts` table via the existing `RecordUnifiedAlert`
  path; `peer_alerts` and `fleet_telemetry` are unchanged.

### What this change does NOT claim or cover

- It does **not** correlate anything. No rules, no incidents, no timeline — that is XDR-4/XDR-5. This
  change only guarantees the input stream is multi-domain.
- It does **not** make every alert in the product a unified alert. It projects **decisions**; a detection
  that never reaches a policy decision (a raw classify hit with no decision published) is not projected,
  and neither is anything arriving on the unverified at-most-once path (D44).
- It does **not** claim the domain mapping is authoritative taxonomy. `EventKind → domain` is a coarse,
  reviewable mapping — `FILE_DELETED` is attributed to `hips` (FIM's tamper signal) rather than `dlp`, a
  deliberate call that a later ticket may revisit; nothing downstream may treat the domain label as more
  than a grouping hint.
- It does **not** de-duplicate across domains or suppress alert storms beyond the existing dedup-key
  behavior (one row per decision id).
- It does **not** address ZT/user-keyed alerts arriving before the access proxy has linked device⋈user:
  such an alert keys to the user alias's own entity, and a later link merges the entities. Ordering
  robustness beyond that merge is out of scope.
