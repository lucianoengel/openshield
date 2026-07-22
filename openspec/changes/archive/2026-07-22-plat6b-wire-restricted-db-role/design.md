# Design — wire the restricted DB role

## A LOGIN role, not SET ROLE

The complete SEC-6 fix is a NON-OWNER role the app connects as. A prior idea — connect as the owner
and `SET ROLE openshield_writer` — is no boundary: `RESET ROLE` returns to the owner, so a
compromised app re-escalates. A real LOGIN role that is merely a MEMBER of openshield_writer cannot
RESET to the owner (it never was the owner). Verified empirically and in the test: after
`RESET ROLE`, the app role still cannot `DISABLE TRIGGER` (must be owner).

## One app role, ledger-constrained + aggregate-DML

The app writes both the ledger (audit_entries/key_epochs/anchors) and the aggregate tables. Rather
than two roles, openshield_writer becomes the one non-owner application role: ledger tables keep
their careful INSERT/UPDATE-only grant (DELETE withheld; the 010 trigger enforces append-only
regardless of grant and cannot be disabled without ownership), and the aggregate tables get full
DML. `ALTER DEFAULT PRIVILEGES` covers future tables so a later migration does not silently break a
non-owner app.

## Migrate-as-owner, run-as-app

The app both migrates (needs owner) and runs (should not be owner) with one DSN — resolved by
`MigrateIfNeeded`: a fresh DB under the owner migrates; an already-migrated DB under the app role
skips via the read-only `fullyMigrated` check. The deploy runs `openshield-server migrate` once as
the owner (which also provisions the app login role), then starts the long-running binaries as the
non-owner role.

## The real-adversary test

`TestAppRoleCannotBypassLedgerBoundary` provisions the app role, connects as it, does the app's
writes (aggregate insert + a real ledger append), then attempts the exact DDL an attacker holding
the app credential would — `DISABLE TRIGGER` (twice: directly and after `RESET ROLE`) and `DELETE`
from the ledger — asserting each fails. Crucially it CONTRASTS with the owner, who genuinely CAN
disable the trigger (then re-enables it), so the app's failures are proven to be a real
authorization boundary, not an operation that is impossible for everyone (a false pass). The
observe-e2e script additionally runs the shipped engine binary as the non-owner role end to end,
appending to the forward-secure ledger.
