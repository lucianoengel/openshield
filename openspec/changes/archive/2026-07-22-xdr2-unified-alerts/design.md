## Context

XDR-1 (D203) gives `Server.graph` (an `*xdr.Store`) that resolves a `(kind, value)` to a durable entity
id, coalescing a device/user across domains. SIEM-6b/ADR-10 (D178) made `peer_alerts` carry
severity/status/dedup_key and stated "a future cross-domain detector writes the same shape". This
increment makes that shape a real, entity-keyed table and writes the first producer into it.

## Goals / Non-Goals

**Goals:**
- One normalized alert table every domain can write, keyed by the XDR entity (not a bare subject string).
- An entity-keyed writer that resolves through the real graph, so alerts join to the device/user model.
- A cross-domain query (`AlertsForEntity`) — the input XDR-4 correlation reads.
- Prove the alert⋈device-entity join on the REAL peer-UEBA path, and that two domains' alerts for one
  subject share one entity.

**Non-Goals:**
- Wiring every domain's producer (DLP verdicts, HIPS kills, NIPS hits, ZT denials) — each is a follow-on
  increment; this builds the table + writer + one producer.
- The correlation engine itself (XDR-4: same-entity multi-domain window/sequence rules → incidents).
- Migrating `peer_alerts` into `unified_alerts` — peer_alerts stays (it carries UEBA-specific
  risk_score/context_version); the unified row is the normalized projection the correlation layer reads.
- IP/session alias kinds (external logs keyed by host/IP need those, a future XDR-1 extension).

## Decisions

1. **A NEW `unified_alerts` table, not an extension of `peer_alerts`.** peer_alerts is UEBA-specific;
   forcing every domain into its risk_score/context_version columns is wrong. `unified_alerts` is
   domain-agnostic: `entity_id, domain, subject_id, severity, title, dedup_key, status, detected_at`.
   The `entity_id` (from the XDR graph) is the correlation key; `domain` labels the source. Indexed by
   `(entity_id, detected_at)` for the per-entity cross-domain read and by `dedup_key` for idempotency.

2. **`RecordUnifiedAlert` resolves the entity via the graph.** It calls `graph.Resolve(subjectKind,
   subject)` → entity_id, then inserts. So the alert is bound to the SAME entity the device/user graph
   resolved (D203) — a peer-UEBA alert for a device pseudonym lands on the exact entity enrollment/ingest
   created, making cross-domain grouping an entity JOIN. A `nil` graph or a resolve error is counted
   (`UnifiedAlertFailures`) and the alert is NOT written (it would be unkeyed and uncorrelatable) — but
   this never breaks the producer's own recording (peer_alerts is still written).

3. **Dedup on `dedup_key`.** `INSERT … ON CONFLICT (dedup_key) DO NOTHING` — the same logical alert
   (same detector-namespaced key) is one unified row, so a re-detection does not multiply correlation
   input. The key is the producer's (e.g. "peer-ueba:<subject>").

4. **Peer-UEBA is the first producer.** `recordPeerAlert` already writes peer_alerts; after it, the
   server records a unified alert (domain="ueba", KindDevice, subject) best-effort. Best-effort because
   the unified projection is derived — a failure there must not fail the authoritative peer_alerts write.

## Risks / Trace-offs

- **Two writes per peer alert (peer_alerts + unified_alerts).** Peer alerts are cooldown-throttled and
  low-frequency; the second write is cheap and dedup-guarded. Acceptable for the correlation it enables.
- **Only one producer wired this increment.** Honest scope: the table + writer + query are the
  foundation; the acceptance ("a HIPS KILL and a DNS alert share an entity key") is met as each producer
  is wired in follow-ons. The `domain` column and the entity join are proven now with peer-UEBA + a
  second-domain write in the test.
- **Subjects that don't resolve to a device entity.** A subject the graph has never seen resolves
  first-sight (creating the entity), so an alert always keys to an entity — consistent with how ingest
  and enrollment create device entities (D203). Non-device subjects (IP/host) await IP alias kinds.
