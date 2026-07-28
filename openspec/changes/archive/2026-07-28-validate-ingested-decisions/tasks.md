# Tasks

- [x] 1. `internal/controlplane`: add `DecisionContractViolations` (the D348 guard will require it on
      `/metrics`).
- [x] 2. `projectDecisionAlert`: validate before projecting; on failure count, log which check failed
      and which agent sent it, and return without projecting.
- [x] 3. REVERSED after checking the producing side, and the check is why. `confidenceFrom` returns 0.0
      for an alertable decision when the policy sets no confidence over an event with no classification
      hits — the NIPS-3 DNS-tunnel rule shipped in D341 is exactly that shape. Refusing absent
      confidence would refuse those alerts. `hasConfidence` is passed true; absence grades LOW, which
      is not a forgery vector, and out-of-RANGE still is and is still refused.
- [x] 4. Unit tests: out-of-range confidence, unknown action, and missing policy identity each produce
      no alert; a well-formed decision still does.
- [x] 5. Driven through the REAL verified-ingest path in `internal/controlplane` — signed envelopes,
      embedded NATS, real Postgres — rather than a separate integration file, because that harness
      already exists there and the gap was never in ValidateDecision but in nothing calling it.
- [x] 6. Mutation-verify: remove the validation call → the forged decision becomes a CRITICAL alert.
- [x] 7. Targeted tests green; decision record; spec sync on archive.
