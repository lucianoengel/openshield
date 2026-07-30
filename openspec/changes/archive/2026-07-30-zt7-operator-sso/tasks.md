# Tasks

- [x] Extract `verifyCore` so the operator path shares every fail-closed JWT check with the ZTNA path.
- [x] `VerifySubject` — raw subject, no role claim required; comment why both differences exist.
- [x] Allow an empty role claim in `NewOIDCVerifierWithSource`; ZTNA path still requires one.
- [x] `SetOperatorOIDC` / `authenticateOperator`; certificate wins when both are present.
- [x] No certificate means no legacy fallback — SSO operators are strict by construction.
- [x] Wire into `openshield-server` with a live JWKS refresher; half-configured is a startup failure.
- [x] Declare the four settings.
- [x] Tests: no-record denial, demotion on an issued token, revocation on an issued token, unverifiable
  token is 401, SSO off unless configured.
- [x] Mutation: letting the token alone authorize must fail the no-record test.
- [x] `make quick` green; targeted package tests only.
