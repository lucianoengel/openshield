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

### Requirement: Signed telemetry is verified before it is persisted
The control plane MUST verify signed telemetry — the signature against the ENROLLED agent key and
the sequence for replays — before persisting it, attribute it to the VERIFIED agent, and REJECT and
count telemetry that fails (bad signature, unknown or revoked agent, replay). A sequence gap MUST be
recorded, not silently accepted.

Per-agent identity (D44) exists but was never applied to the telemetry stream, so the fleet view was
self-asserted (D41) and suppression undetectable. Verifying on ingest makes telemetry attributable
and gaps visible — the evidentiary bar telemetry needs.

#### Scenario: A validly signed message is verified and stored as attributable
- **WHEN** an enrolled agent publishes correctly signed telemetry
- **THEN** it verifies and is persisted attributed to that agent, marked verified
- **AND** a test drives it over an embedded NATS and asserts the stored, verified row

#### Scenario: An unverifiable message is rejected and counted
- **WHEN** telemetry arrives with a bad signature, from an unknown or revoked agent, or replaying a
  sequence
- **THEN** it is NOT persisted and a rejection is counted
- **AND** tests assert each case increments the rejection count and stores nothing

#### Scenario: A sequence gap is recorded
- **WHEN** a validly signed message arrives with a sequence beyond the next expected
- **THEN** the message is stored and the gap is recorded
- **AND** a test asserts the gap is observable

### Requirement: Verified and self-asserted telemetry are distinguishable
Persisted telemetry MUST record whether it was verified against an enrolled key or arrived on the
legacy unsigned path (self-asserted). The unsigned path MUST NOT be silently treated as verified.

An aggregate that cannot tell attributable telemetry from self-asserted invites the same overclaim
the project forbids — presenting unverified data as evidence. The distinction must be in the data.

#### Scenario: The stored row carries its verification status
- **WHEN** telemetry is persisted via the signed path and via the legacy unsigned path
- **THEN** the signed one is marked verified and the legacy one is marked self-asserted
- **AND** a test asserts both

### Requirement: peer alerts are a derivation, stored apart from received telemetry
The control plane MUST store a server-side peer alert in a store DISTINCT from the received-telemetry
store, because a peer alert is a control-plane DERIVATION, not an agent-attested message, and letting
a derivation sit among received rows would let it masquerade as fleet-attested evidence.

A peer alert MUST carry the pseudonymous subject, the peer-relative risk score and the context
version (D27), and MUST be recorded only after the triggering telemetry has itself verified (D50).
The peer-alert store is NOT the evidentiary ledger (D38); it is a fleet-aggregate detection surface.

#### Scenario: A peer alert is persisted separately and read back
- **WHEN** an enabled control plane records a peer alert for an outlier subject
- **THEN** the alert is written to the peer-alert store with subject, risk score and context version,
  not to the received-telemetry store
- **AND** a test reads the alert back and confirms it is absent from the telemetry rows

### Requirement: an anomalous subject raises at most one alert per rising edge
The control plane MUST throttle repeat peer alerts for a still-anomalous subject with a cooldown, so
one outlier does not emit an alert on every subsequent event while its risk stays high.

The cooldown throttles the ALERT, not the risk computation — risk is still evaluated each event; only
re-alerting within the window is suppressed. This is a rate limiter, not a change to the signal.

#### Scenario: Many events from one outlier yield one alert
- **WHEN** an outlier subject sends many events in quick succession, each above the risk threshold
- **THEN** the control plane records one peer alert for that subject within the cooldown window, not
  one per event
- **AND** a test asserts the alert count is one, not the event count

### Requirement: A restarted agent's telemetry is not rejected as a replay
The control plane MUST accept telemetry from an agent that has restarted with a persisted, forward
sequence — recording a gap if one occurred — rather than rejecting it as a replay, so a routine restart
does not silently drop an agent's telemetry.

#### Scenario: Post-restart telemetry is accepted, not replayed
- **WHEN** an agent restarts, resumes from its persisted high-water sequence, and publishes
- **THEN** VerifySigned accepts the telemetry (a gap at most), not ErrReplay
- **AND** a test drives a restart-then-publish and asserts acceptance, not replay rejection


### Requirement: The fleet aggregate has an enforced retention window
The control plane MUST purge the fleet aggregate (received telemetry and derived peer alerts) older
than a configurable window, on a periodic timer. Because the fleet aggregate is a derived detection
view and not the evidentiary ledger, its purge is a hard delete; the number of rows removed is logged.

#### Scenario: Aggregate rows past the window are deleted, recent rows kept
- **WHEN** the fleet-aggregate purge runs with a cutoff
- **THEN** telemetry and peer-alert rows older than the cutoff are deleted and rows newer than it remain

### Requirement: The operator has a read API over peer alerts and overdue agents
The control plane MUST expose operator-authenticated read endpoints for the recent peer alerts and the
overdue agents, behind the same mutual-TLS operator-role gate as the investigation view. The endpoints
MUST be read-only (hold no signer) and MUST return pseudonymous, boundary-safe fields only. A
non-operator (agent) cert MUST get 403.

#### Scenario: An operator reads peer alerts and overdue agents
- **WHEN** an operator-role client requests the alerts and overdue endpoints
- **THEN** it receives the recent peer alerts and the overdue agents as JSON

#### Scenario: A non-operator is refused
- **WHEN** an agent-role client requests those endpoints
- **THEN** it is refused with 403
