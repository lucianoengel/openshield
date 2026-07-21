# network-gateway delta

## ADDED Requirements

### Requirement: Tunneled flows are recorded as a metadata-only audit entry
The gateway MUST record a metadata-only ledger entry for every flow it tunnels without inspection
(both the blind tunnel when interception is off and a do-not-intercept host when it is on), naming the
destination host and the reason it was not inspected, with NO body, NO URL path, and NO decision — so
uninspected egress is visible in the audit trail rather than silent. The recording MUST be best-effort:
an append failure is logged and the tunnel still proceeds. An inspected (intercepted) flow MUST NOT
record a tunnel entry — its Decision is recorded instead, so the two paths are distinct in the ledger.

#### Scenario: A blind-tunneled flow records a metadata-only tunnel entry
- **WHEN** an HTTPS flow is tunneled without inspection
- **THEN** the ledger records a "tunneled" entry naming the destination host and the reason, with no
  decision and no body

#### Scenario: A do-not-intercept host records a tunnel entry with that reason
- **WHEN** interception is on but the host is on the do-not-intercept list
- **THEN** the flow is tunneled and a "tunneled" entry records the host with reason do-not-intercept

#### Scenario: An intercepted flow records a decision, not a tunnel entry
- **WHEN** a flow is intercepted and inspected
- **THEN** its Decision is recorded and no "tunneled" entry is written
