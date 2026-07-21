## Why

An incident (F2) needs a place to live and a workflow to resolve — Phase F3 adds
case/investigation management. The security core is FOUR-EYES (D36): closing a case must
require two distinct operators, so no single operator can unilaterally close and bury an
investigation.

## What Changes

- Migration `011_cases.sql`: `cases` (subject, status, opened/assigned/close_requested/
  closed-by, timestamps) + `case_notes`.
- `Server.{OpenCase, AssignCase, AddNote, RequestClose, ApproveClose, GetCase}`. ApproveClose
  is FOUR-EYES: it refuses an approver equal to the requester (`ErrFourEyes`), enforced both
  up front and in the atomic UPDATE predicate. Actors are the operator's VERIFIED cert
  identity (D56).

## Capabilities

### Modified Capabilities
- `control-plane`: an operator case workflow with four-eyes closure.

## Impact

- New migration, `internal/controlplane/cases.go`; `docs/decisions.md` D105.
- Proven (Postgres): open → assign → note → request-close by Alice → Alice CANNOT approve
  her own closure (ErrFourEyes, case stays open) → Bob (a different operator) approves and
  the case closes, recording BOTH parties; approving a closure that was never requested is
  refused. Four-eyes mutation-tested: it is enforced by TWO independent guards (an up-front
  check + the atomic UPDATE predicate) — removing EITHER alone preserves the control
  (defense in depth), removing BOTH is caught.
- NOT in scope (stated): the case HTTP endpoints (the workflow methods are here behind the
  operator gate's identity; wiring POST routes is a follow-up); case-from-incident
  auto-creation (F2 produces incidents, an operator opens a case — linking them is a
  follow-up); the UI (F4); notice/DPIA (T-013 remainder). Subjects pseudonymous (D23);
  every action attributed to a verified operator cert (D56), never self-asserted.
