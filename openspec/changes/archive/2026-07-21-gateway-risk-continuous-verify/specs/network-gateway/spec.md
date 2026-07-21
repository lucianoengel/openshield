# network-gateway delta

## ADDED Requirements

### Requirement: The gateway performs continuous verification on published risk, deciding locally
The gateway MUST be able to read a published per-subject risk score and enrich the access decision
context with it, so a policy can step-up or deny a subject whose risk has risen mid-session. The
decision MUST be made by the local policy reading the risk as data — the server MUST NOT command the
gateway to cut access. Absent risk MUST NOT itself deny (it means analytics is quiet, not danger),
unlike absent device posture which fails closed; the presence of a risk score MUST be distinguishable
from its absence.

#### Scenario: Rising risk cuts access mid-session, decided locally
- **WHEN** an authorized identity accesses a service, then a high risk score is published for that
  subject, then it accesses again
- **THEN** the first access is allowed and the second is denied by the local policy, with the service
  not reached

#### Scenario: Absent risk does not deny an authorized identity
- **WHEN** an authorized identity accesses a service and no risk is published for it
- **THEN** access is allowed (absent risk is not high)
