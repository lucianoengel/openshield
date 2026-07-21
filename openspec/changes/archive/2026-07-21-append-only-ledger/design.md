## Context

`audit_entries` (migration 001) columns split into two sets: the INTEGRITY
SKELETON that the hash chain and forward-secure signatures commit to —
`sequence, appended_at, prev_hash, hash, sig, key_epoch, retention_class,
context_version` — and CONTENT columns the D36 retention tombstone nulls
(`decision_id, event_id, action, confidence, reason, policy_id, policy_version,
outcome_kind, outcome_stage, subject_id, purpose`) plus `tombstoned_at`. Retention
(`ledger.Purge`) UPDATEs only content + `tombstoned_at`, keeping the skeleton so a
tombstoned row stays a verifiable link (D36).

## Goals / Non-Goals

**Goals:**
- Reject, at the DB, any DELETE and any UPDATE that mutates a skeleton column —
  so a leaked connection string cannot rewrite or truncate history via SQL.
- Keep the retention tombstone working (content-only UPDATE + tombstoned_at).
- Keep `Verify()` proven against a trigger-bypassing adversary.

**Non-Goals:**
- Full least-privilege role separation (a non-owner ledger role) — the complete
  fix, documented as a follow-up. This change is the DB-level append-only control
  that does not require a role/DSN split.
- Encryption at rest, RLS, or protecting against a superuser/table-owner who
  disables the trigger (that is what `Verify()` + anchoring are for).

## Decisions

**A BEFORE UPDATE OR DELETE row trigger, not column GRANTs.** Column-level
`GRANT UPDATE (…)` would require a separate non-owner role (a bigger operational
change). A trigger enforces the same append-only invariant on the existing role
without a DSN split, and encodes the tombstone exception precisely. The trigger:
- `TG_OP = 'DELETE'` → raise (append-only; deletion breaks the chain, D36).
- UPDATE where any skeleton column `IS DISTINCT FROM` its old value → raise.
- UPDATE clearing `tombstoned_at` (non-NULL → NULL) → raise (erasure is one-way).
- otherwise allow (the retention tombstone and any future content-only edit).

**The tamper tests model a bypassing adversary.** The existing tests raw-mutate
skeleton columns to (a) simulate tampering and (b) fast-forward `appended_at` for
retention-age tests. Both are things the production trigger now blocks. They route
through `bypassAppendOnly(t, pool, func)` which does
`ALTER TABLE audit_entries DISABLE TRIGGER USER` → the mutation →
`ENABLE TRIGGER USER`. This is faithful: it models an attacker who got PAST the DB
control (a superuser, or someone who disabled the trigger), and asserts `Verify()`
STILL detects the tamper. So the two layers are tested independently — the trigger
blocks the ordinary DSN-holder (new positive test), and `Verify()` blocks the
bypasser (existing tests, now via the helper).

**Positive guard.** A new test opens the ledger, appends entries, and asserts:
`pool.Exec` DELETE of a row → error (trigger); UPDATE of `hash` → error; a
retention-style tombstone UPDATE (content-only) → success. This proves the trigger
is installed and shaped correctly.

## Risks / Trade-offs

- **A table OWNER can disable the trigger.** The pooled role owns the table
  (migrations created it), so it CAN `DISABLE TRIGGER` — meaning a determined
  DSN-holder who knows this can still bypass. Stated plainly: this stops the
  SQL-level / backup-restore / opportunistic attacker, not a determined one; the
  COMPLETE fix is a non-owner restricted role (follow-up), and the guarantee
  against a bypasser is `Verify()` + external anchoring (D38), not this trigger.
  Overstating it would be exactly the overclaim the project guards against.
- **Retention must never touch a skeleton column.** If a future retention change
  tried to modify one, the trigger would (correctly) reject it — a loud failure,
  not silent corruption. The tombstone column list is asserted by the positive
  test so drift is caught.
- **Trigger overhead on writes.** A row trigger runs per append/tombstone; the
  cost is a few column comparisons — negligible against the append's hashing and
  signing.
