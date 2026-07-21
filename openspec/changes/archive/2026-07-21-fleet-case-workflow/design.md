## Context

F2 produces incidents; F3 is the human workflow to investigate and resolve them. The
distinguishing requirement is four-eyes on closure (D36).

## Goals / Non-Goals

**Goals:** a case lifecycle (open/assign/note/close) with four-eyes closure, attributed to
verified operator identities.

**Non-Goals:** HTTP routes; incident→case linking; UI; notice/DPIA.

## Decisions

**Four-eyes enforced twice — defense in depth.** ApproveClose refuses an approver equal to
the requester both with an UP-FRONT check (for a clear ErrFourEyes) AND in the atomic UPDATE
predicate (`close_requested_by <> $1`), so two operators racing cannot both slip through and
a single operator cannot self-approve. The mutation tests confirm each guard alone preserves
the control and removing both is caught — the redundancy is the point.

**Every actor is a verified certificate identity (D56).** opened_by / assigned_to /
close_requested_by / closed_by are `operator:<CN>` from the mTLS client cert, never a
self-asserted string — the same discipline as view-audit. A case's trail is attributable.

**Close is a two-step: request then approve.** RequestClose sets status and records the
requester; ApproveClose (by a different operator) closes. A case cannot be closed in one
step, which is what makes four-eyes meaningful.

## Risks / Trade-offs

- **Methods, not yet routes.** The workflow is exposed as server methods behind the
  operator gate's identity; the HTTP surface (POST /cases, etc.) is a thin follow-up, kept
  separate so the four-eyes logic is proven independently of transport.
- **No case reopening / audit of state transitions yet.** The status field supports it; a
  full transition log is a follow-up.
