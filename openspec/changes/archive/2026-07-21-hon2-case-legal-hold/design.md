## Context

Legal hold must survive a routine purge. The mechanism the audit suggested (retention_class =
investigation) collides with the append-only trigger's immutable skeleton, so a registry is
the right shape.

## Goals / Non-Goals

**Goals:** opening a case holds the subject's evidence; a queryable active-hold state.

**Non-Goals:** the purge respecting it (SEC-5); auto-release on close.

## Decisions

**A registry, not a retention_class flip.** Migration 010 makes `audit_entries.retention_class`
immutable (the hash chain and signatures commit to it), so it cannot be changed after the fact.
The hold is a separate `legal_holds` table keyed by the pseudonymous subject, which the purge
consults — the ledger row is never mutated, and the append-only invariant is preserved.

**Placed in the case's transaction.** OpenCase/OpenCaseForIncident place the hold in the SAME
transaction as the case — a case without its hold would leave evidence purgeable. Idempotent
via a partial unique index (one active hold per subject) + ON CONFLICT DO NOTHING, so two cases
on one subject do not error.

**Release is recorded, not deleted.** ReleaseLegalHold sets released_at rather than deleting
the row, so the hold history is itself auditable.

## Risks / Trade-offs

- **Hold is keyed by subject, not by specific entries.** A subject under investigation has ALL
  their evidence held — coarse but safe (over-retention, not under). Entry-level holds are a
  follow-up if needed.
- **Cross-store assumption:** the registry and the ledger share a database in the current
  deployment. A split deployment would need the hold to propagate — noted.
