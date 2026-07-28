# Tasks

- [x] 1. `internal/config`: add `OPENSHIELD_SMTP_LISTEN` (bootstrap, string, empty disables), beside
      `OPENSHIELD_DNS_LISTEN`.
- [x] 2. `cmd/openshield-engine/smtpsource.go`: bind the listener and adapt its sink into the event
      channel, mirroring `dnssource.go` — monotonic flow id, source IP carried, send races context.
- [x] 3. `cmd/openshield-engine/main.go`: start it when configured, tracked in the WaitGroup so the
      event channel is not closed while it produces; startup line states capture-not-MTA, no-TLS,
      observe-only.
- [x] 4. Integration scenario: a real SMTP session with a checksum-backed CPF in the body, asserted
      on the AUDIT ROW and on the decision being an ALERT.
- [x] 5. Integration: `assertLedgerCarriesNone` over the body's sensitive value.
- [x] 6. Mutation-verify: the source not wired (the pre-change state) → no audit entry; the body
      replaced by a non-checksum-valid value → no alert, proving the classification ran.
- [x] 7. Targeted tests green; decision record; spec sync on archive.
