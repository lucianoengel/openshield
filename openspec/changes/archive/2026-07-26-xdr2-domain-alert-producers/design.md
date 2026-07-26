## Context

`unified_alerts` exists, is entity-keyed, dedups, and has a per-entity read (`AlertsForEntity`) — but a
single producer: `recordPeerAlert` projects the server-side peer-UEBA detection. Every other domain stops
at its own record.

What already reaches the control plane, verified, from every domain:

- `internal/engine/telemetry.go:projectTelemetry` — the endpoint engine publishes `Event` then `Decision`
  for every DLP / HIPS detection.
- `internal/gateway/telemetry.go:projectTelemetry` — the gateway publishes a redacted `Event` then the
  `Decision` for every network / DNS / SMTP flow **and** for the ZT access proxy's authorization
  (`access.go` → `gw.Process`).
- Both go through `natsx.SignedPublisher` → `openshield.v1.signed`, and land in
  `controlplane.handleSigned`, which verifies the signature and monotonic sequence before persisting to
  `fleet_telemetry`.

So the raw material for a multi-domain alert stream is already ingested and already verified. What is
missing is the projection.

Two facts shape the design:

1. **A `Decision` is subject-less and kind-less.** It carries `decision_id`, `event_id`, `action`,
   `confidence`, `reason`, policy identity, `decided_at`. The entity key and the domain live on the
   `Event`.
2. **Signed telemetry is monotonic per agent**, and both producers publish `Event` *then* `Decision` on
   the same publisher. So when a decision is ingested, its event row is already persisted.

## Goals / Non-Goals

**Goals:**

- Every domain's alertable decision lands in `unified_alerts`, keyed to the same entity the entity graph
  knows for that subject — so XDR-4 has a genuinely cross-domain input.
- Zero change to producers, to the frozen core, or to any proto/migration. This is a control-plane
  read-side projection.
- Preserve derived-index discipline (D38): the projection cannot alter, delay, or fail ingest.
- Keep the boundary (D10/D29): nothing content-bearing enters the alert row.

**Non-Goals:**

- Correlation rules, incidents, timelines (XDR-4/XDR-5).
- Projecting raw classification hits that never produced a decision.
- Projecting the unverified legacy `handle()` path.
- A domain taxonomy richer than the coarse `EventKind → domain` mapping.

## Decisions

### D-1: Project at verified ingest, from the Decision

**Chosen:** hook `handleSigned` after the telemetry transaction commits; project `kind == "decision"`.

*Alternatives:*

- **Project from each producer (agent/gateway writes its own unified alert).** Rejected: it would put a
  control-plane database write on the endpoint's critical path, cross the process boundary the design
  spent D13/D72 establishing, and require every producer to learn the entity graph. The producers already
  ship the facts; the server owns the derived index.
- **Project at query time (a view over `fleet_telemetry`).** Rejected: `unified_alerts` is the physical
  correlation input with a dedup key and a lifecycle `status`; a view cannot dedup a re-detection and
  would re-decode protobuf payloads on every correlation pass.
- **Project from the `Event` rather than the `Decision`.** Rejected: an event is not an alert. The
  decision is the point where the pipeline asserts something is wrong, and it carries the action that
  gives the alert its severity.

### D-2: Recover subject + kind by joining back to the persisted event

The projection reads the originating `event` row: `SELECT payload FROM fleet_telemetry WHERE kind='event'
AND event_id=$1 AND verified` and unmarshals it for `Subject.PseudonymousId` and `Kind`.

*Alternatives:*

- **Add subject/kind fields to the `Decision` proto.** Rejected outright: `decision.proto` is the most
  security-sensitive contract in the system, and widening it to carry identity would weaken the
  "enforcers see only the Decision" separation for no gain — the server already holds the event.
- **Keep an in-memory event→subject cache keyed by event id.** Rejected as the primary mechanism: it
  loses everything on restart and re-introduces a race the durable row does not have. The row lookup is
  one indexed query on the same transaction's data.

**Ordering.** The event is published before the decision on the same monotonic signed publisher, and the
control plane's subscription callback processes envelopes in order, so the event row is committed first.
If it is nonetheless absent (a subject-less event rejected by the R34-12 contract, a decision whose event
predates enrollment, a producer that publishes decisions without events), the projection **does not
guess**: it counts and returns. This is the "unfed stream" detector — the counter is the signal that a
domain is failing to reach correlation.

### D-3: `EventKind → domain` is a total mapping over the closed enum

`file-opened/modified/created`, `usb-inserted` → `dlp`; `process-exec`, `ransomware-suspected`,
`memory-injection-suspected`, `file-deleted` → `hips`; `network-flow`, `http-request`, `dns-query`,
`smtp-message` → `nips`. Unspecified → not projected.

Two calls worth naming: `file-deleted` goes to `hips` (it exists as the FIM tamper signal, not as a DLP
verdict), and the ZT access proxy's denials arrive as `http-request` and therefore land under `nips`
rather than a `zt` domain — the proxy reuses the network event shape, and inventing a `zt` domain would
require distinguishing access from egress, which the Event does not currently express. Both are recorded
in the proposal as deliberate, revisitable choices; nothing downstream may read the domain label as more
than a grouping hint. The alternative (a new `EventKind` or an event field for "access vs egress") is a
contract change and is not worth it for a label.

### D-4: Severity from the closed action set, title from closed enums only

`severityForDecision(action, confidence)` = `Severity(confidence)`, floored at `high` for the enforcement
actions (BLOCK, DENY_EXEC, KILL_PROCESS, QUARANTINE_LOCAL, ENCRYPT_LOCAL, REDIRECT). `ALERT` keeps the
confidence bucket. Reusing `Severity()` keeps one risk→bucket mapping (ADR-10) rather than a second scale
that drifts.

The title is built from the `Action` and `EventKind` enum names only. Using `Decision.reason` would be
the easy, wrong choice: it is policy-authored free text that can quote a path or a hostname, and
`unified_alerts` is a widely-read derived table. The test asserts the stored title against seeded
content-bearing fields.

*Alternative considered:* a per-domain severity table. Rejected as premature — nothing yet distinguishes
a `high` from one domain vs another, and the closed action set already carries the impact signal.

### D-5: Entity keying prefers an existing alias of ANY kind

`xdr.Store` gains `LookupAny(ctx, value) (int64, bool, error)` — resolve by alias value across kinds,
creating nothing. `RecordUnifiedAlert` calls it first and falls back to `Resolve(kind, value)`.

This is the load-bearing correctness fix. The access proxy links `KindDevice(D) ⋈ KindUser(U)`, and its
events carry `U` as the subject. Under device-only resolution the projection would call
`Resolve(KindDevice, U)` → **no such alias** → mint a new `device` alias holding a user value → a second
entity. The ZT domain would then sit on an entity of its own and never join the host's other domains —
a silent, plausible-looking correlation hole exactly of the kind this project's test discipline exists to
catch. The mutation test removes `LookupAny` and asserts the fork.

Placing it inside `RecordUnifiedAlert` (rather than only in the new projection) means the peer-UEBA
producer benefits identically, and there is one keying rule in the system.

*Risk of the kind-agnostic lookup:* two different kinds could in principle hold the same value string and
be conflated. In practice the namespaces are disjoint by construction (device values are
`pseudonym.Of(agentID)` / `sub_<hash>` derivations, user values are the OIDC identity), and a collision
would mean the same string genuinely does name both. Accepted, and stated.

### D-6: Observability

One new counter for decisions that could not be projected (originating event missing or subject empty),
alongside the existing `UnifiedAlertFailures` for graph/insert failures. A correlation stream that
quietly stops being fed is the failure mode that would make XDR-4 look broken; both counters are exported
through the existing metrics surface.

## Risks / Trade-offs

- **The event row is missing when the decision is projected** (out-of-order delivery, a rejected
  subject-less event, a producer publishing decisions without events) → the alert is dropped, counted,
  and never guessed. Chosen over writing an unkeyed or agent-keyed row, which would pollute correlation
  with rows that group wrongly. The counter makes the drop visible.
- **One extra indexed SELECT + protobuf unmarshal per alertable decision at ingest** → bounded: it runs
  only for non-ALLOW decisions (the minority), after the ingest transaction has committed, and never
  blocks the ack path's correctness. Allowed decisions cost one enum comparison.
- **A domain label that is coarse** (ZT denials under `nips`, `file-deleted` under `hips`) → stated in
  the proposal as revisitable; no downstream consumer may treat it as authoritative taxonomy. The
  alternative is an Event contract change, which is a far larger risk for a label.
- **Alert volume** — every non-ALLOW decision now writes a row. Dedup is per decision id, so a noisy
  policy produces many rows. Accepted for this increment (correlation needs the input); rate/burst
  suppression belongs with XDR-4, which is where "too many alerts" becomes visible as too many incidents.
- **`LookupAny` conflating two kinds that share a value** → see D-5; disjoint by construction, accepted
  and documented.

## Migration Plan

None required: no schema change, no proto change, no config flag. The projection begins on deploy of the
control plane; existing rows are unaffected, and no backfill of historic decisions is attempted (a
backfill would fabricate `detected_at` ordering for alerts nobody triaged). Rollback is the previous
control-plane binary.

## Open Questions

- Should the ZT access proxy eventually get its own `zt` domain? It needs the Event to distinguish access
  from egress; deferred to whenever XDR-4's rules show that grouping ZT with `nips` loses signal.
- Should a *classification* with no decision ever be projected? Currently no; revisit if a domain turns
  out to alert without deciding.
