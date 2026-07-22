## Context

The append-only trigger (010) stops a leaked connection string / backup-restore attacker but
not the owner, who can disable it. The complete fix is a non-owner app role.

## Goals / Non-Goals

**Goals:** the app runs under a role that cannot ALTER/disable the trigger, DELETE, or DROP.

**Non-Goals:** deploy credential provisioning; SEC-5(b).

## Decisions

**Connect AS a non-owner role — not SET ROLE from the owner.** A SET ROLE from an
owner-authenticated connection is bypassable: RESET ROLE returns to owner privileges. The real
boundary is the app authenticating as a distinct login role that is a MEMBER of
openshield_writer (INHERIT) and NOT a member of the owner — it never has owner rights to
regain. The test proves this with a real login role: it can append but cannot disable the
trigger, delete, drop, or SET ROLE to the owner.

**Migrate only when needed.** Migrations CREATE tables/triggers/roles — owner-only. A non-owner
app cannot run Migrate, so Open first does a READ-ONLY `fullyMigrated` check (does
schema_migrations exist and hold every embedded migration?) and skips Migrate when the DB is
current. The deploy runs migrations once as the owner; the app connects as the writer role.

## Risks / Trade-offs

- **Two credentials** (owner for migrations, writer for the app) — the correct posture, but the
  deploy must provision the writer login (a password). The migration creates the privilege set;
  the login role + password is a deploy step (PLAT-6).
- **A leaked WRITER credential** can append and tombstone (both chain-visible / Verify-checkable)
  but cannot rewrite or erase history — the bar the trigger + Verify + anchoring already assume.
