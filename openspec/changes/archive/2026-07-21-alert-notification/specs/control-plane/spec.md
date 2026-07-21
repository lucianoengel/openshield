# control-plane delta

## ADDED Requirements

### Requirement: Alerts are delivered to a configured sink, best-effort
The control plane MUST be able to deliver alerts to a configured notification sink (a webhook) in
addition to recording them, so a human is told rather than having to poll. A peer-UEBA alert MUST
trigger a notification when it is recorded. Delivery MUST be best-effort: a sink error is logged and
counted, never propagated — a down sink MUST NOT break telemetry ingest or the detection, because the
alert is already recorded and delivery is additive.

#### Scenario: A webhook receives an alert as JSON
- **WHEN** a notification is delivered to a configured webhook
- **THEN** the sink receives the notification as JSON with its kind and fields

#### Scenario: A failed delivery does not break ingest
- **WHEN** the sink returns an error
- **THEN** the recorded alert stands and telemetry processing continues
