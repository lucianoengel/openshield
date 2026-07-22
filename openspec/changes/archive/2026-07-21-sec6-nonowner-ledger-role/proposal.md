## Why

SEC-6 (P1). Migration 010's append-only trigger is honest-bounded: a table OWNER can DISABLE
it, so DB-level append-only was only advisory against a leaked OWNER credential — and the
shipped DSN uses the owner. The complete fix (named in 010's own comment) is running the app
under a NON-OWNER restricted role. This ships it.

## What Changes

- Migration `013_writer_role.sql`: an `openshield_writer` role with SELECT/INSERT/UPDATE on the
  ledger tables (the trigger constrains which UPDATE), no DELETE, no ownership.
- `Ledger.Open` migrates ONLY WHEN NEEDED (a read-only `fullyMigrated` check), so a non-owner
  app can Open on an already-migrated DB without owner rights. The deploy runs migrations once
  with the owner DSN, then points the app at a writer-role DSN.

## Capabilities

### Modified Capabilities
- `audit-ledger`: the app can run under a non-owner role that cannot weaken the append-only guard.

## Impact

- New migration, `internal/store/postgres/{ledger,migrate}.go`; `docs/decisions.md` D125.
- Proven (Postgres, a REAL non-owner LOGIN role that is a member of openshield_writer): it can
  Open (migration skipped) and APPEND, but CANNOT disable the append-only trigger, DELETE, DROP
  the table, or SET ROLE to the owner — a real boundary. Guard mutation-tested (force
  fullyMigrated false → the non-owner Open tries to migrate and is denied).
- Deliberately NOT the weaker SET-ROLE-from-owner approach: an owner connection that SET ROLEs
  to the writer can RESET ROLE back to owner — no boundary. This connects the app AS the
  non-owner role, the only real fix.
- NOT in scope (stated): the deploy's writer-login-role credential provisioning (a login role
  with a password is a deploy step — the migration creates the privilege set; compose/systemd
  wiring to a writer DSN is a packaging follow-up, PLAT-6); SEC-5(b) per-purge attribution.
