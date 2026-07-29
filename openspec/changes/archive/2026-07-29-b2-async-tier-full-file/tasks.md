# Tasks

- [x] 1. `cmd/openshield-engine`: a dedicated worker pool for gate verdicts, separate from the
      classification pool, with the startup line saying why it exists.
- [x] 2. A bounded, TTL'd path-dedupe: submitting async for a path suppresses further submissions for
      that path until it expires. Bounded because the keys are attacker-influenced.
- [x] 3. After answering a gate question, submit the event to the async tier unless the path is
      suppressed.
- [x] 4. Unit tests for the dedupe: one path submits once, a different path submits, an entry expires,
      the cache does not grow without bound.
- [x] 5. Integration: a gated open produces BOTH the inline verdict and a subsequent full-file
      classification — with a detectable value placed PAST the inline prefix, so the second
      classification is the only thing that could have found it.
- [x] 6. VM: the cycle TERMINATES under a real mark. Bounded assertion, ALLOW before DENY, every
      command under `sudo -n timeout N`.
- [x] 7. Mutation: remove the dedupe → resubmission is unbounded. Capped so the mutant demonstrates the
      loop without bricking the host.
- [x] 8. Runbook: the extra gate round trip per async classification, beside the prefix-size guidance.
- [x] 9. Targeted tests green; decision record; spec sync on archive.
