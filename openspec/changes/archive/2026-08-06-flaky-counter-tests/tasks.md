# Tasks — flaky counter tests

- [x] 1. Count before answering on every refusal path in `handleSOCKS`.
- [x] 2. Move the method-negotiation refusal's counting INTO `socksNegotiateMethod`, where the write is,
      and stop the caller counting it twice.
- [x] 3. Extend the SOCKS tests so the counter is asserted on the BIND and uncatalogued-target paths too,
      not only the ticket refusal.
- [x] 4. Add a `startCorrelationLoop` test helper that cancels AND joins the loop before the pool closes;
      use it in both callers.
- [x] 5. Say in the `CorrelationFailures` assertion that a non-zero count may be another test's leak.
- [x] 6. Prove: 10+ runs of each affected test (the gateway one also under `-race`), and the controlplane
      package as a whole.
- [x] 7. Mutate each fix back and record whether the test fails — and, for the gateway, whether it fails
      reliably or only sometimes.
- [x] 8. Found underneath flake 2: stopping the loop counted as a correlation failure. Suppress it, with
      a test whose cancellation is fired from the per-tick provider so the mutation kills 10 of 10.
- [x] 9. Roadmap notes point at the fix; new decision row.
