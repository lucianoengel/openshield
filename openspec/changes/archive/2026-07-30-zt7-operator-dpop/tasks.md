# Tasks

- [x] `VerifySubjectWithProof` on the existing DPoP validator: raw subject, no role claim, require-bound flag.
- [x] Refuse a bound token when proofs cannot be checked, rather than downgrading it.
- [x] Read the `DPoP` header in `authenticateOperator`; build `htu` with a hardcoded scheme.
- [x] Enable proof validation on the operator verifier; declare the settings.
- [x] Narrow the verifier interface to the proof-aware method only.
- [x] Semantics tested against the REAL verifier after a mutation showed the stub tests blind to it.
- [x] Mutations: no-proof honoured, switch ignored, silent downgrade — all three must fail.
- [x] `make quick` green; targeted package + integration tests only.
