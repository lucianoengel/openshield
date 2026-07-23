## Why

XDR-1 wired the entity graph (D203) — enrollment, ingest, and the gateway now coalesce a device/user to
ONE entity. But correlation is still single-domain: `Correlate()` reads only `peer_alerts`, and each
domain's detections live in their own shapes (peer-UEBA in `peer_alerts`, DLP/HIPS/NIPS as telemetry).
For the XDR promise — "one incident per attack across domains" (XDR-4) — every domain's detections must
land in ONE normalized, ENTITY-KEYED alert stream that a single correlation engine reads. This is XDR-2,
the spine step after XDR-1/SIEM-6b. This increment builds that stream and its entity-keyed writer, and
wires the first real producer (server-side peer-UEBA); wiring the remaining domains is the follow-on.

## What Changes

- **A `unified_alerts` table**: domain-agnostic, keyed by `entity_id` (the XDR-1 graph entity), carrying
  `domain` (which detection domain), subject, severity, title, a detector-namespaced dedup_key, and the
  ADR-10 lifecycle (status, detected_at). One shape every domain writes; one table the correlation
  engine reads.
- **`Server.RecordUnifiedAlert(domain, subjectKind, subject, …)`**: resolves the subject to an entity
  via the XDR graph (`graph.Resolve`) and inserts a unified alert — so an alert is bound to the SAME
  entity the device/user graph knows, making cross-domain grouping an entity join, not a string match.
- **`Server.AlertsForEntity(entityID)`**: all domains' alerts for one entity, newest first — the
  cross-domain view XDR-4 correlation will consume.
- **First producer wired**: server-side peer-UEBA (`recordPeerAlert`) now ALSO records a unified alert
  (domain="ueba"), best-effort (a unified-alert failure never breaks the existing peer alert).

## Capabilities

### New Capabilities
- `unified-alerts`: a normalized, entity-keyed alert stream every detection domain writes and one
  correlation engine reads — the foundation of cross-domain correlation.

### Modified Capabilities
<!-- none in this increment: peer-UEBA gains a unified-alert write, but its own alert behavior is
     unchanged. -->

## Impact

- `internal/store/postgres`: migration `025_unified_alerts.sql` (entity-keyed alert table + indexes).
- `internal/controlplane`: `UnifiedAlert` type; `RecordUnifiedAlert` (entity-resolving writer);
  `AlertsForEntity`; a `UnifiedAlertFailures` counter; peer-UEBA wired to record one.
- `internal/store/postgres/postgres_test.go`: migration count 24 → 25.
- No proto/core change, no new dependency. Wiring DLP/HIPS/NIPS/ZT producers + the cross-domain
  correlation over this table (XDR-4) are follow-on increments.
