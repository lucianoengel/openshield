# Tasks — CONSOLE-5

## 1. Schema

- [x] 1.1 Migration `053_view_audit_retention.sql`: add `route` and `query` to `investigation_views`
      (both `NOT NULL DEFAULT ''`, so no existing row or reader changes meaning), plus a `viewed_at`
      index the purge needs.

## 2. Recording

- [x] 2.1 `recordViewDetail` writes the five fields; `RecordView` keeps its signature and delegates, so
      the four existing call sites and their tests are untouched.
- [x] 2.2 `ViewRecord`, `Views`/`ViewsBy` and `GET /views` carry `route` and `query`.
- [x] 2.3 `canonicalViewQuery`: parameters sorted, capped at 512 bytes, truncation marked in the value.
- [x] 2.4 `viewAudited` wraps the operator read mux: records GET/HEAD before the handler runs, refuses
      with 500 when the record fails (handler not invoked), 500 with no principal.
- [x] 2.5 `viewAuditedInHandler` and `viewAuditExempt` tables, each entry carrying its reason; the two
      are disjoint and everything else records by default.
- [x] 2.6 Wire the wrapper once at the mount in `enroll_http.go`.

## 3. Retention

- [x] 3.1 `OPENSHIELD_VIEW_AUDIT_RETENTION` in `internal/config/server.go` (dynamic, duration, `8760h`,
      `LoweringWeakens`) and in the sensitivity test's enumeration.
- [x] 3.2 `PurgeViewsOlderThan`.
- [x] 3.3 Wire it into the leader-only retention loop in `cmd/openshield-server/main.go`, recording the
      compliance event under target `investigation_views` with the policy string built from the value
      actually used (D333).

## 4. DSAR

- [x] 4.1 `SubjectReport.ViewsOfSubject`, counted from `investigation_views` by `subject_filter`.

## 5. Tests (each mutation-verified, with the mutation named in a comment)

- [x] 5.1 The record exists BEFORE the handler runs (inner handler reads the table).
- [x] 5.2 A failing record refuses the read and the handler never runs.
- [x] 5.3 An audited path records and an exempt path does not — both halves in one test.
- [x] 5.4 No principal → 500 and no row.
- [x] 5.5 Query canonicalisation and marked truncation.
- [x] 5.6 The two route tables are disjoint, every exemption carries a reason, and every decision names
      a route the server actually mounts.
- [x] 5.7 `PurgeViewsOlderThan` deletes past the cutoff and keeps inside it.
- [x] 5.8 The DSAR counts views naming the subject and reports zero rather than omitting.
- [x] 5.9 Integration: the SHIPPED server records each audited route and not `/health`.
- [x] 5.10 Integration: the shipped leader purges the view audit and records the compliance event.

## 6. Documentation

- [x] 6.1 `docs/threat-model.md`: the insider section says which reads are recorded and which are not.
- [x] 6.2 `docs/decisions.md` row; `docs/architecture-roadmap.md` CONSOLE-5 entry and table row.
- [x] 6.3 Sync the delta into `openspec/specs/{control-plane,operator-identity}/spec.md`, validate,
      archive.
