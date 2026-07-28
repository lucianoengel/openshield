# Tasks

- [x] 1. `internal/config`: add `OPENSHIELD_DNS_TUNNEL_THRESHOLD` as `KindUnitInterval`, default
      0.5, with a description stating that the score is a product of two clamped signals so values
      near 1.0 are reachable only in principle.
- [x] 2. `internal/policy/mapping.go`: for an event whose kind is `EVENT_KIND_DNS_QUERY`, compute
      `dns.TunnelScore` over the queried name and expose `event["dns"] = {"tunnel_score": ...}`.
      Absent for every other event kind.
- [x] 3. `internal/policy/default.rego`: add the alert rule, gated on the threshold, with a comment
      recording why it alerts rather than blocks.
- [x] 4. Thread the threshold from configuration into policy evaluation the way the existing
      thresholds are threaded; report it on the engine's startup line.
- [x] 5. Unit tests in `internal/policy`: a tunnelling name alerts, an ordinary name does not, a
      non-DNS event has no `dns` input, and every policy pack still composes (the pack-composition
      test must keep passing — a new default rule must not be disabled by enabling a pack).
- [x] 6. Unit test in `internal/config`: an out-of-range threshold is refused, naming the field.
- [x] 7. Integration scenario: a live DNS listener, a real UDP query, assertions on the AUDIT ROW.
      Both halves — ordinary name does not alert, tunnelling name does.
- [x] 8. Integration: `assertLedgerCarriesNone` over the encoded labels.
- [x] 9. Mutation-verify: (a) the mapping does not compute the score → the tunnelling query stops
      alerting; (b) the rule's comparison is inverted or the threshold ignored → the ordinary name
      alerts. Both must FAIL the scenario.
- [x] 10. Correct the false claim in `cmd/openshield-engine/dnssource.go`'s doc comment.
- [x] 11. Targeted tests green (policy, config, the DNS integration scenario); decision record;
      spec sync on archive.
