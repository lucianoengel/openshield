# Tasks

- [x] Integration case: role change + revocation via the real CLI against the running mTLS server.
- [x] Integration case: SSO end to end against the real binary, with static issuer keys.
- [x] `ServerConfigOptionalClientCert`, applied only when operator SSO is configured.
- [x] `OPENSHIELD_OPERATOR_OIDC_KEYS_DIR`; refuse both key sources at once.
- [x] Separate operator verifier constructors; ZTNA keeps requiring a role claim.
- [x] Assert an untrusted client certificate is STILL refused — and fix that assertion after a mutation
  showed it passing for the wrong reason.
- [x] Mutation: `RequestClientCert` (presented but unverified) must fail the test.
- [x] `make quick` green; targeted package + integration tests only.
