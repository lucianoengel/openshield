# dns-connector (delta)

## ADDED Requirements

### Requirement: The DNS listener bounds its admission rate
The DNS listener MUST bound the rate at which it admits datagrams into the pipeline with a global
rate limit, so a datagram beyond the sustained rate is dropped before it produces a pipeline event —
a spoofed-source query flood cannot grow the audit ledger at wire speed. The rate-limit drops MUST be
counted separately from parse drops, so a flood is observable.

#### Scenario: A flood beyond the rate is dropped before minting events
- **WHEN** the listener receives far more datagrams than its admission rate allows
- **THEN** only the datagrams within the burst/rate are delivered to the sink and the excess are dropped and counted as rate-limited
