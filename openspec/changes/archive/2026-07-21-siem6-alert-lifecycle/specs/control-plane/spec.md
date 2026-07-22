# control-plane (delta)

## ADDED Requirements

### Requirement: Peer alerts carry a severity and can be acknowledged
The control plane MUST derive a severity bucket for each peer alert and correlated incident from
its risk score, exposing it on the read surfaces, and MUST support filtering alerts by a minimum
severity. The control plane MUST let an operator acknowledge an alert, recording the
acknowledgement time and the acknowledging operator's VERIFIED identity (from the mutual-TLS
client certificate, never a caller-supplied name). Acknowledgement MUST be first-ack-wins — a
later acknowledgement of an already-acknowledged alert MUST NOT overwrite the original triager —
and acknowledging a non-existent alert MUST be an error, not a silent no-op. The control plane
MUST support filtering to only unacknowledged alerts, so an operator can work the actionable
queue. The acknowledgement surface MUST be operator-gated and mutating (rejecting a read method).

#### Scenario: An operator acknowledges an alert and works the unacknowledged queue
- **WHEN** an operator acknowledges an alert and then lists unacknowledged alerts at or above a severity
- **THEN** the alert is recorded acknowledged by the verified operator, a second acknowledgement does not change the triager, acknowledging a phantom id errors, and the acknowledged alert no longer appears in the unacknowledged queue while lower-severity alerts are excluded by the severity floor
