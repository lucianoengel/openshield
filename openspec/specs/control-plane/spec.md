# control-plane Specification

## Purpose
The server side: subscribes to agent telemetry over NATS and persists it to a fleet AGGREGATE store — distinct from and NOT carrying the agent forward-secure ledger evidentiary guarantees; only boundary-safe summaries can arrive, malformed messages are counted not dropped, and it coordinates/observes without distributing policy or controlling agents.
## Requirements
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

### Requirement: Serving an investigation records who viewed it
When the control plane serves an investigation, it MUST record the view — viewer, what was queried,
and when — so that obtaining the evidence and leaving a record are one operation. The recorded
viewer MUST carry an identity marker and MUST be labelled unauthenticated until an authenticated
operator identity exists.

D20 requires the trail cover who VIEWED, not only who acted. The write surface that can record it is
the control plane (the CLI is a signer-less verifier, D30). Serving-and-recording atomically means a
caller cannot read the evidence without being logged. The unauthenticated label keeps a self-asserted
OS identity from being mistaken for a verified operator.

#### Scenario: A served investigation leaves a labelled view record
- **WHEN** an investigation is served through the control plane with a viewer identity
- **THEN** a view record is written carrying the viewer (labelled unauthenticated), what was queried,
  and the time, and the telemetry is returned
- **AND** a test asserts the record, the label, and that the view is readable back

#### Scenario: A bare, unlabelled viewer is refused
- **WHEN** a view is recorded with an empty viewer
- **THEN** it is rejected, so no unattributable view is silently recorded

### Requirement: The view log states its limits
The view log MUST be documented as non-evidentiary and its viewer as self-asserted — it is not the
forward-secure ledger, and the viewer is not authenticated.

A compromised control plane could alter or omit a view record, and the viewer is an OS identity, not
a verified operator. Presenting the view log as tamper-proof accountability would be the overclaim
the project forbids; the honest value is a recorded, readable trail of who looked, with its limits
named.

#### Scenario: No surface claims the view log is tamper-evident
- **WHEN** the view log is described
- **THEN** it is described as non-evidentiary with a self-asserted, unauthenticated viewer, and
  operator authentication is named as an unbuilt sibling gap

