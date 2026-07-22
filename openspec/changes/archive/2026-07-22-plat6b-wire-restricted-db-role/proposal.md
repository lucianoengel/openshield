# PLAT-6b: wire the restricted DB role (closes SEC-6)

## Why

Migration 013's `openshield_writer` role and migration 010's append-only trigger are real and
tested — but **no shipped config uses the role**. `compose.yaml`, every `deploy/systemd/*.service`,
and the e2e scripts connect as the table OWNER (`openshield:dev`), and an owner can `ALTER TABLE …
DISABLE TRIGGER`. So the DB-level append-only boundary — the thing protecting the crown-jewel
ledger against a leaked connection string — protects nothing in the running product. SEC-6's actual
condition is the wiring, and it was never done.

## What Changes

- **Migration 017** makes `openshield_writer` the COMPLETE non-owner application privilege set:
  the ledger tables stay append-only-constrained (their 010 trigger + no DELETE grant), and the
  aggregate tables get full DML, with `ALTER DEFAULT PRIVILEGES` so future tables auto-grant.
- **`postgres.EnsureAppLogin`** idempotently provisions a NON-OWNER LOGIN role (member of
  `openshield_writer`) — the identity the app connects as. Being a real login role, it cannot
  `RESET ROLE` back to the owner (the flaw that made SET-ROLE-from-owner no boundary).
- **`openshield-server migrate`** — an owner-run one-shot that applies migrations and provisions the
  app role; **`postgres.MigrateIfNeeded`** lets the app binaries start as the non-owner role (they
  skip Migrate via the read-only `fullyMigrated` check).
- **Deploy wiring**: `compose.yaml` gets a `migrate` one-shot (owner) that the app services depend
  on and then connect as the non-owner role; a new `openshield-migrate.service` systemd unit with
  the app units ordered after it and repointed to the non-owner DSN; the e2e scripts migrate-as-
  owner then run the long-running binaries as the non-owner role.

## Impact

- Affected specs: `packaging`
- Affected code: migration `017`, `internal/store/postgres/migrate.go` (EnsureAppLogin,
  MigrateIfNeeded, validRoleName), `cmd/openshield-server` (migrate subcommand + MigrateIfNeeded),
  `compose.yaml`, `deploy/systemd/*`, `deploy/*-e2e.sh`, plus a real-adversary boundary test.
- Not in scope (stated): rotating/secret-managing the app-role password (PLAT-5/PLAT-6 — a dev
  default `app` is used, documented as change-in-production); a separate least-privilege role per
  binary (one non-owner app role suffices to close the owner-bypass; per-binary scoping is a later
  hardening); k8s/Helm manifests (PLAT-6).
