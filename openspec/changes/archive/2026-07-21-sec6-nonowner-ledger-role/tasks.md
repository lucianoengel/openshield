# Tasks — SEC-6 non-owner ledger role (D125)

## 1. Fix

- [x] 1.1 Migration 013 openshield_writer role + grants; Open skips migration when fullyMigrated (read-only), so a non-owner app can Open.

## 2. Proof (Postgres; guard mutation-tested)

- [x] 2.1 **Test**: a real non-owner LOGIN member of openshield_writer can Open (migration skipped) + append, but cannot disable-trigger/delete/drop/become-owner.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D125.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| force fullyMigrated false | the non-owner app Open then tries to Migrate and is denied |
| (role owns table / has DELETE) | the forbidden-ops test would then pass an op — enforced by Postgres via the migration grants |
