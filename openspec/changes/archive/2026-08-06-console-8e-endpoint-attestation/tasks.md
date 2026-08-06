# Tasks — CONSOLE-8e

- [x] 1. Extract `StartAgentAttestation`, `ParsePCRs` and `selfEnroll` into `internal/posture`.
- [x] 2. Move the simulator onto it (112 net lines removed) and move its PCR test with the code.
- [x] 3. Wire the engine, in a goroutine, with a nil-logger-tolerant `ParsePCRs`.
- [x] 4. Declare the five attestation settings on `EngineFields`.
- [x] 5. Integration test with a real software TPM: refused unattested, admitted after — and still
      observing, which is D314's lesson.
- [x] 6. Regression: the pre-existing simulator real-TPM scenario passes unchanged on the shared path.
- [x] 7. Mutation: the engine does not attest.
- [x] 8. Docs: D477 row; the roadmap's simulator-vs-product table closes.
