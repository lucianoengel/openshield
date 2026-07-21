# Tasks — append-only ledger at the database level

## 1. The trigger

- [x] 1.1 Migration `010_append_only.sql`: a plpgsql `BEFORE UPDATE OR DELETE` trigger on `audit_entries` — raise on DELETE; raise on UPDATE that changes `sequence, appended_at, prev_hash, hash, sig, key_epoch, retention_class, context_version`; raise on clearing `tombstoned_at`.
- [x] 1.2 Bump the migration-count assertion in `postgres_test.go` to 10.

## 2. Tests

- [x] 2.1 **Positive guard**: after appends, `pool` DELETE of a row errors, UPDATE of `hash` errors, and a content-only retention-style tombstone UPDATE succeeds.
- [x] 2.2 A `bypassAppendOnly(t, pool, func)` helper: `DISABLE TRIGGER USER` → run → `ENABLE TRIGGER USER`.
- [x] 2.3 Route the existing tamper/aging raw mutations (action tamper, prev_hash, sig, DELETE-truncations, appended_at aging) through `bypassAppendOnly` — they still create the tamper and assert `Verify()` catches it.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D63: the ledger is append-only at the DB level (trigger forbids DELETE + skeleton UPDATE, permits the tombstone); raises the bar from "leaked DSN = rewrite history" to "cannot tamper via SQL"; a table OWNER can disable it, so the complete fix is a non-owner restricted role (follow-up), and Verify()+anchoring (D38) catch a bypasser.
- [x] 3.2 `openspec validate append-only-ledger --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| trigger allows an integrity-column UPDATE (hash/prev_hash) | `TestLedgerIsAppendOnly` |
| trigger permits un-tombstoning | `TestLedgerIsAppendOnly` |
| bypass helper does not actually disable the trigger | the tamper tests (their mutation is blocked → fail) |

**Honest note on DELETE:** removing only the explicit DELETE branch did NOT open
DELETE — on a DELETE `NEW` is NULL, so the skeleton check (`NEW.sequence IS
DISTINCT FROM OLD.sequence`) still raises. DELETE is doubly-guarded (explicit
branch + null-NEW skeleton check); defense in depth, recorded rather than forced.

The ledger is now append-only at the DB level: the app role cannot DELETE a row
or change an integrity column (proven), the retention tombstone still succeeds,
and the existing tamper tests — via an owner-privilege trigger bypass modeling an
adversary who got past the DB control — still prove Verify() catches the bypasser.
