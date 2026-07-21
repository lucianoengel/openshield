## ADDED Requirements

### Requirement: The control plane persists received agent telemetry
The control plane MUST subscribe to the agent telemetry subjects, decode each message, and persist
it to a fleet store keyed by agent, kind and event. A malformed message MUST be recorded and
dropped, not silently vanish and not stall the subscription.

The transport can publish telemetry and nothing consumes it; "the server coordinates" needs a
consumer. Persisting what arrives is that consumer. A malformed message that vanishes silently
would be the same missing-evidence failure the whole system guards against, so a drop is counted.

#### Scenario: Published telemetry is persisted and readable
- **WHEN** an agent publishes an Event, a ClassificationSummary and a Decision, and the control
  plane is subscribed
- **THEN** each is persisted and read back by agent and by event
- **AND** an end-to-end test over an embedded NATS asserts the round trip

#### Scenario: A malformed message is counted, not silently dropped
- **WHEN** a message that does not decode arrives
- **THEN** it is recorded as a decode failure and the subscription continues
- **AND** a test asserts the failure is observable rather than silent

### Requirement: Only boundary-safe telemetry can be received
The control plane MUST NOT be able to receive or store file content or a `LocalClassification`.
Only the `ClassificationSummary` — type, confidence, count — crosses the boundary.

The two-type split (D10) is only worth something if no path exists by which content reaches the
control plane. The transport provides no method for `LocalClassification`, so the guarantee is
structural, and the store inherits it: there is nothing to redact because content never arrives.

#### Scenario: Stored classification carries no content
- **WHEN** a classification is received and read back
- **THEN** it carries only type, confidence and count
- **AND** a test confirms no content or reversible digest is present

### Requirement: The aggregate store is not the evidentiary ledger
Documentation and any surface MUST describe the control-plane store as a fleet AGGREGATE view, not
as tamper-evident evidence. The agent's local hash-chained, forward-secure ledger is the
evidentiary record.

A compromised control plane could alter the aggregate; it has no hash chain or forward-secure
signatures. Presenting it as evidence would be exactly the overclaim the project forbids — the
integrity guarantees live at the agent (D12/D30), externally anchored (T-019), and the aggregate
must not borrow them.

#### Scenario: No surface claims the aggregate is tamper-evident
- **WHEN** the control-plane store is described
- **THEN** it is described as an aggregate view, and the evidentiary record is named as the agent
  ledger
- **AND** the agent_id is noted as self-asserted until identity (T-017) exists
