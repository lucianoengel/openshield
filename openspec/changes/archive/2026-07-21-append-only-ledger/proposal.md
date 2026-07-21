## Why

Audit finding #2a, verified: the ledger is append-only only by CONVENTION.
Migration 001 has no RLS, no `REVOKE`, no append-only trigger; one pooled role
both appends and verifies, and retention performs a raw `UPDATE audit_entries`.
So tamper-EVIDENCE is purely a read-time `Verify()` property — anyone with the
Postgres connection string (a leaked `.env`, a backup, a misconfigured network)
can rewrite or truncate the hash chain with no privilege distinguishable from the
app. The honest bar to compromise history today is "steal a connection string,"
not "get root."

## What Changes

- Migration 010 installs a `BEFORE UPDATE OR DELETE` trigger on `audit_entries`
  that makes it append-only at the DATABASE level:
  - DELETE is always forbidden.
  - UPDATE that changes any INTEGRITY SKELETON column — `sequence`, `appended_at`,
    `prev_hash`, `hash`, `sig`, `key_epoch`, `retention_class`, `context_version`
    — is forbidden.
  - Resurrecting a tombstoned entry (`tombstoned_at` non-NULL → NULL) is forbidden.
- The D36 retention tombstone still works: it only nulls content columns and sets
  `tombstoned_at`, none of which are skeleton columns, so purge/retention is
  unaffected.
- A positive guard proves the app role can no longer DELETE an audit row or change
  a hash (the trigger raises), while a retention tombstone still succeeds.
- The existing tamper-detection and retention-aging tests raw-mutate skeleton
  columns to SIMULATE an attacker or fast-forward time; they now route through a
  helper that briefly disables the user trigger (an OWNER-privilege bypass,
  faithfully modeling an adversary who got PAST the DB control) — so they still
  create the tamper and prove `Verify()` STILL catches it. That is the whole
  point: the trigger is defence in depth, and `Verify()` + external anchoring
  catch anyone who bypasses it.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `audit-ledger`: the ledger is append-only at the database level — DELETE and
  integrity-column UPDATE are rejected by a trigger, so a leaked connection string
  can no longer rewrite or truncate history via SQL, while the retention tombstone
  and `Verify()` are preserved.

## Impact

- New: migration `010_append_only.sql`; a positive guard test; a trigger-bypass
  test helper wrapping the existing raw tamper/aging mutations; migration-count
  bump to 10; docs (D63).
- HONEST residual, stated: a table OWNER can `DISABLE TRIGGER`, so the COMPLETE
  fix is running the ledger under a NON-OWNER restricted role (a documented
  follow-up). This migration raises the bar from "leaked connection string =
  rewrite history" to "leaked connection string cannot tamper via SQL, and a
  determined bypass is still caught by `Verify()` + anchoring (D38)." Respects
  D30 (forward-secure chain), D36 (tombstone), D38 (anchoring bounds truncation).
