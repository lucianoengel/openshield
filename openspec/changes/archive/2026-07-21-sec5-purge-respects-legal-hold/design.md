## Context

The purge tombstones by class + age. HON-2 records legal holds in a registry (because
retention_class is immutable). SEC-5 connects them: the purge must skip held subjects.

## Goals / Non-Goals

**Goals:** a legal-held subject's evidence survives the purge, at any routine class/age.

**Non-Goals:** the per-purge attribution audit entry (SEC-5 b); the non-owner DB role (SEC-6).

## Decisions

**A registry override on age enforcement.** The purge keeps its per-class age cutoffs and adds
`subject_id NOT IN (SELECT subject_id FROM legal_holds WHERE released_at IS NULL)`. An active
hold protects the subject regardless of the entry's class — necessary because the class is
immutable, so a later investigation cannot re-class already-written evidence. Releasing the
hold restores normal purge eligibility.

**Same database.** The registry and the ledger share a database in the current deployment, so
the exclusion is a subquery. A split deployment would need the hold to propagate (noted).

## Risks / Trade-offs

- **Coarse (per-subject) hold** — over-retention, not under; safe for evidence.
- **Attribution audit entry (SEC-5 b) deferred** — the purge protects held evidence now; making
  every purge itself chain-visible is the follow-up.
