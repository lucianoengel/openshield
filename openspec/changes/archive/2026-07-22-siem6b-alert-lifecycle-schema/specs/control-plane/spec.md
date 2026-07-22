## MODIFIED Requirements

### Requirement: Peer alerts carry a severity and can be acknowledged
The control plane MUST record a severity bucket, a correlation/dedup key, and a status lifecycle
(`open` → `triaged` → `closed`) as FIRST-CLASS fields on each peer alert, so a uniform alert lifecycle
is available to cross-domain detectors and cross-host correlation, not derived only at read time. The
severity MUST be stamped at write from the alert's risk (so it is correct for the recorded alert), the
correlation key MUST namespace the detector so keys from different detectors do not collide, and the
status MUST start `open`. The control plane MUST expose the severity on the read surfaces and MUST
support filtering alerts by a minimum severity. The control plane MUST let an operator acknowledge an
alert, recording the acknowledgement time and the acknowledging operator's VERIFIED identity (from the
mutual-TLS client certificate, never a caller-supplied name) AND advancing the alert's status beyond
`open`. Acknowledgement MUST be first-ack-wins — a later acknowledgement of an already-acknowledged
alert MUST NOT overwrite the original triager — and acknowledging a non-existent alert MUST be an
error, not a silent no-op. The control plane MUST support filtering to only unacknowledged alerts, so
an operator can work the actionable queue. The acknowledgement surface MUST be operator-gated and
mutating (rejecting a read method).

#### Scenario: An operator acknowledges an alert and works the unacknowledged queue
- **WHEN** an operator acknowledges an alert and then lists unacknowledged alerts at or above a severity
- **THEN** the alert is recorded acknowledged by the verified operator, a second acknowledgement does not change the triager, acknowledging a phantom id errors, and the acknowledged alert no longer appears in the unacknowledged queue while lower-severity alerts are excluded by the severity floor

#### Scenario: An alert carries first-class lifecycle fields and acknowledgement advances the status
- **WHEN** a peer alert is recorded and later acknowledged
- **THEN** the recorded alert carries a stored severity, a detector-namespaced dedup/correlation key, and status `open`, and after acknowledgement its status has advanced beyond `open`
