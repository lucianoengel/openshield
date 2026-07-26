## 1. The approval object

- [x] 1.1 Migration 031: `approvals(id, subject_kind, subject_id, state, requester, approver, reason,
  requested_at, resolved_at, expires_at)` + an index on `(subject_kind, subject_id)`; one pending approval
  per subject enforced by a partial unique index. Bump the migration count.
- [x] 1.2 `RequestApproval(ctx, kind, subjectID, requester, ttl)` and `ResolveApproval(ctx, id, approver,
  approve bool)` with the requester≠approver AND not-expired AND still-pending comparisons all inside the
  UPDATE predicate; typed errors for each refusal.
- [x] 1.3 `ApprovalFor(ctx, kind, subjectID)` so a consumer can find the decision for its subject.

## 2. Tests

- [x] 2.1 Requester cannot approve their own request; a different operator can. **Mutation:** move the
  comparison out of the predicate into a pre-check only → the concurrent test FAILS.
- [x] 2.2 Concurrency: N operators approve simultaneously → exactly one succeeds.
- [x] 2.3 Expiry: an approval after the TTL is refused as expired. **Mutation:** drop `expires_at > now()`
  → FAILS.
- [x] 2.4 Terminal: a resolved request cannot be resolved again, and the original attribution is unchanged.
- [x] 2.5 Subject binding: an approval for one subject does not satisfy another.

## 3. Rewire case closure

- [x] 3.1 `RequestClose`/`ApproveClose` backed by an approval, signatures and behavior unchanged; the
  existing case tests are the regression gate and must pass untouched.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Roadmap + decision register; state that nothing but case closure consumes it until SOAR-4/7.
- [x] 4.3 Commit `SOAR-3`, sync spec, archive.
