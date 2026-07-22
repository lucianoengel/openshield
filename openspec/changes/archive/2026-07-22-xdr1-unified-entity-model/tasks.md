# Tasks

## 1. Migration
- [x] 1.1 `internal/store/postgres/migrations/021_entities.sql`: `entities(id BIGSERIAL PK, created_at
  TIMESTAMPTZ DEFAULT now())` and `entity_aliases(entity_id BIGINT REFERENCES entities(id), kind TEXT,
  value TEXT, first_seen TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(kind, value))` + an index on entity_id.
- [x] 1.2 Bump the migration-count contract test in `postgres_test.go` (20 → 21).

## 2. Entity store
- [x] 2.1 `internal/xdr/store.go`: `Store{pool}`; `KindDevice`/`KindUser` constants; `Resolve(ctx, kind,
  value) (int64, error)` — tx + `pg_advisory_xact_lock(hashtext(kind|value))` then select-or-insert
  (atomic find-or-create).
- [x] 2.2 `Link(ctx, kindA, valA, kindB, valB) (int64, error)` — tx locking both aliases in sorted order,
  resolve each, and if different MERGE: repoint the loser's aliases to the older (winner) entity, delete
  the loser; return the winner id. Idempotent when already linked.

## 3. Tests (real Postgres)
- [x] 3.1 `Resolve` twice → same id; a second distinct alias → a different id.
- [x] 3.2 Canonical join: `Resolve(KindDevice, pseudonym.Of("agent-A"))` from two call sites (an "exec"
  and a "gateway request") → the SAME entity id (using the real derivation, not a literal).
- [x] 3.3 Concurrency: N goroutines `Resolve` the same new alias → all get one id and exactly one entity
  row exists.
- [x] 3.4 `Link` merges two separate entities → both aliases resolve to one id, the loser entity is gone;
  `Link` again is idempotent.

## 4. Mutation guards
- [x] 4.1 Skip the find (SELECT-existing) in `Resolve` so it always inserts → `TestResolveIsStable`
  FAILs (the second resolve of the same alias hits the (kind,value) PK and errors). NOTE: the PK is the
  ultimate duplicate-guard; the advisory lock avoids the conflict-ERROR path under concurrent first-sight
  (the concurrency test 3.3 confirms clean concurrent resolves). Revert.
- [x] 4.2 Make `Link` not repoint the loser's aliases (skip the merge UPDATE) → the merge test (3.4)
  FAILs (the aliases still resolve to different entities). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D195) — XDR-1 entity model; canonical-pseudonym join (IDENT-1
  hard-dep); atomic find-or-create + lock-ordered merge; Postgres system-of-record; XDR-3/2/4 follow-ups.
- [x] 5.2 `docs/architecture-roadmap.md`: mark XDR-1 shipped; note the XDR spine's next steps.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/entity-model/spec.md`.
