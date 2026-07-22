## Why

HON-2 (P1). The case workflow (D105/D107) is implemented, but NOTHING sets a legal hold —
opening a case did not actually HOLD its linked evidence, so a purge (past normal age) could
erase it, and SEC-5's legal-hold guarantee had nothing to protect. This wires case-open → hold.

## What Changes

- Migration `012_legal_holds.sql`: a `legal_holds` registry (subject_id, held_by, reason,
  held_at, released_at; one active hold per subject).
- `Server.{ReleaseLegalHold, IsUnderLegalHold}` + `placeLegalHoldTx`; `OpenCase` and
  `OpenCaseForIncident` place an active hold on the subject in the SAME transaction as the case.

## Capabilities

### Modified Capabilities
- `control-plane`: opening a case places a legal hold on the subject's evidence.

## Impact

- New migration, `internal/controlplane/cases.go`; `docs/decisions.md` D122.
- Design note: the audit suggested flipping `audit_entries.retention_class` to the
  investigation class, but migration 010's append-only trigger makes `retention_class` an
  IMMUTABLE integrity column (the hash chain commits to it) — an UPDATE changing it is
  rejected. So the hold is a SEPARATE registry keyed by the pseudonymous subject (D23),
  consulted by the purge (SEC-5), never mutating the immutable ledger row.
- Proven (Postgres): opening a case (and opening from an incident) places an active hold;
  IsUnderLegalHold is true for a held subject and false for a free one; releasing ends it; a
  second case on the same subject is idempotent (no error). Guards mutation-tested (OpenCase/
  OpenCaseForIncident don't place a hold; IsUnderLegalHold ignores released_at). Also fixed
  the test DROP list to include the case/legal-hold tables (a leaked hold masked a mutation —
  the recurring test-hygiene lesson).
- NOT in scope (this ticket): the purge RESPECTING the hold (SEC-5, next — this is the setter
  it depends on); auto-release on case close (release is a method; wiring it into ApproveClose
  is a small follow-up so a closed case's hold can be lifted deliberately).
