# control-plane delta

## ADDED Requirements

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
