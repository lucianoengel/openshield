# Tasks — SEC-5 purge respects legal hold (D123)

## 1. Fix

- [x] 1.1 Ledger.Purge excludes subjects in legal_holds WHERE released_at IS NULL.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: a routine-class held subject survives purge, an unheld one is tombstoned; after release, a later purge tombstones it.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D123.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| drop the legal-hold exclusion | the held subject's evidence is purged |
| ignore released_at | a released hold still protects (the post-release purge tombstones 0) |
