# control-plane delta

## ADDED Requirements

### Requirement: The control plane correlates alerts into incidents by a burst rule
The control plane MUST correlate peer alerts into incidents by grouping a subject's alerts
within a time window and above a risk floor, raising an incident only when the count reaches
a threshold. An incident MUST carry the subject, the alert count, the peak risk, and the
first and last times. A subject below the threshold, outside the window, or below the risk
floor MUST NOT raise an incident. The correlation MUST be parameterized (operator input as
data) and its endpoint MUST sit behind the operator-role gate.

#### Scenario: A burst raises an incident and a quiet subject does not
- **WHEN** the correlation rule runs over the alert aggregate
- **THEN** a subject with enough alerts in the window raises one incident with its count and peak risk, while a single-alert or out-of-window subject does not, and a non-operator is refused
