# Tasks — SEC-2 enrollment cannot hijack/un-revoke (D114)

## 1. Fix

- [x] 1.1 Enroll: ON CONFLICT DO NOTHING + ErrAgentExists on zero rows (no token consumed).

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: a hijack re-enroll of an existing id is refused (ErrAgentExists), victim key still verifies, attacker key does not; a revoked agent cannot be un-revoked and stays revoked.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D114.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| restore ON CONFLICT DO UPDATE | the attacker's key then verifies as the victim (hijack) |
| drop the existing-agent refusal | re-enrollment then succeeds instead of ErrAgentExists |
