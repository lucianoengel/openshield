## Context

`ApproveClose` (D36) is the only four-eyes control in the tree. It gets the hard part right — the
requester≠approver comparison is in the `UPDATE ... WHERE close_requested_by <> $1` predicate, so a race
cannot produce two closes — and it is welded to `cases` columns (`close_requested_by`, `closed_by`).

SOAR-4 (`wait-for-approval` steps), SOAR-7 (high-impact intents gated on approval) and SOAR-8 (IdP responder,
"four-eyes always") each need the same control over a different subject.

## Goals / Non-Goals

**Goals:** one approval object; the atomic predicate preserved; expiry; terminal outcomes; case closure
rewired onto it with unchanged behavior.

**Non-Goals:** approval policy (how many, for what — the caller decides), notification/routing (SOAR-9),
identity governance.

## Decisions

### D-1: A subject KIND plus a subject id, not a foreign key

`(subject_kind, subject_id)` rather than a typed FK per consumer. A response-intent id and a playbook-step
id do not live in one table, and adding a nullable FK column per consumer is how the `cases` version got
welded in the first place. The pair is opaque to this package: it only guarantees an approval for one
subject cannot satisfy another.

### D-2: The predicate stays in the UPDATE

Every state change is a single `UPDATE ... WHERE state='pending' AND requester <> $approver AND expires_at > now()`.
The pre-read exists only to produce a specific error; correctness comes from the predicate. Moving the
comparison into Go would reintroduce exactly the race the original got right.

### D-3: Expiry is a column, evaluated in the predicate — not a sweeper

`expires_at > now()` in the WHERE clause means an expired request is unapprovable the instant it expires,
with no background job to fall behind. A separate `ExpirePending` sweep exists only to make the STATE
readable (`expired` rather than a stale `pending`), and is therefore cosmetic-but-honest rather than
load-bearing: even if it never ran, an expired request could not be approved.

### D-4: Case closure is rewired, not duplicated

`RequestClose`/`ApproveClose` keep their signatures and behavior, backed by an approval. If the two
implementations coexisted, the four-eyes rule would have two homes and a future fix would land in one.

## Risks / Trade-offs

- **Rewiring a shipped control is the risk here.** Mitigated by keeping the existing case tests unchanged as
  the regression gate: if closure behavior moved, they fail.
- **`(kind, id)` is stringly-typed.** Accepted for the reasons in D-1; the kinds are constants in one place.
- **One approver, always.** N-of-M is not modelled; if SOAR-8 later needs two approvals for an IdP action,
  that is an extension, and pretending the current shape covers it would be the overclaim.

## Migration Plan

Additive: a new `approvals` table. Existing `cases` columns stay (historical closures keep their
attribution) and are written alongside the approval for continuity.
