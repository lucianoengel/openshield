# Tasks

- [x] 1. `internal/controlplane/metrics.go`: render the eight unexposed counters, help text stating
      what a non-zero value means.
- [x] 2. `internal/controlplane`: keep a reference to the syslog listeners (atomically published) and
      render their RateLimited / Oversize / Dropped counters; absent when no listener runs.
- [x] 3. `internal/controlplane`: a guard test reflecting over the Server struct's atomic.Int64 fields,
      failing when one is not rendered — and correct the false comment claiming the CEF counters were
      already exposed.
- [x] 4. `cmd/openshield-engine`: periodic discard report for the DNS and SMTP listeners, emitted only
      when a counter has moved.
- [x] 5. Unit test: the guard fails for a counter that is not rendered (verified by mutation, not by
      assertion alone).
- [x] 6. Integration: assert the counters are SCRAPABLE from a running server, and that a listener's
      counters are ABSENT when no listener runs and PRESENT when one does.
      DEVIATION, recorded rather than glossed: the plan said "flood past the admission rate". The
      limiter is 5000/sec with a 10000 burst, so a flood means >10k datagrams over loopback — slow and
      timing-dependent, and it would prove the limiter works (already unit-tested) rather than that the
      counter is reachable, which is what was broken. The absent-vs-present pair is the isolating
      property and is deterministic.
- [x] 7. Targeted tests green; decision record; spec sync on archive.
