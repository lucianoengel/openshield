## 1. Schema

- [x] 1.1 Migration `025_unified_alerts.sql` — `unified_alerts(id, entity_id, domain, subject_id, severity, title, dedup_key UNIQUE, status, detected_at)` + `(entity_id, detected_at)` index.
- [x] 1.2 Bump migration-count test 24 → 25.

## 2. Store + writer + query

- [x] 2.1 `UnifiedAlert` type; `Server.RecordUnifiedAlert(ctx, domain, subjectKind, subject, severity, title, dedupKey, at)` — resolve entity via `graph.Resolve`, INSERT ON CONFLICT(dedup_key) DO NOTHING; count + skip on resolve failure (`UnifiedAlertFailures`).
- [x] 2.2 `Server.AlertsForEntity(ctx, entityID)` — all domains' alerts for an entity, newest first.

## 3. Wire the first producer

- [x] 3.1 Peer-UEBA `recordPeerAlert` also records a unified alert (domain="ueba", KindDevice, subject), best-effort — a unified failure never breaks the peer_alerts write.

## 4. Tests (real PG; mutation-verified)

- [x] 4.1 Real peer-UEBA outlier path → a unified alert lands (domain=ueba); its entity_id EQUALS the device entity the graph resolved for the subject (alert⋈device-entity join, not a tautology).
- [x] 4.2 Cross-domain: record a second alert (domain="dlp") for the SAME subject → `AlertsForEntity` returns BOTH, sharing the entity id.
- [x] 4.3 Dedup: the same dedup_key twice → one row.
- [x] 4.4 Mutations: `RecordUnifiedAlert` stores the subject instead of resolving the entity → the join/`AlertsForEntity` test FAILs; dropping the ON CONFLICT → the dedup test FAILs.

## 5. Gate + close

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 5.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 5.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
