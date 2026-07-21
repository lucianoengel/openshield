# control-plane delta

## ADDED Requirements

### Requirement: The operator has a read API over peer alerts and overdue agents
The control plane MUST expose operator-authenticated read endpoints for the recent peer alerts and the
overdue agents, behind the same mutual-TLS operator-role gate as the investigation view. The endpoints
MUST be read-only (hold no signer) and MUST return pseudonymous, boundary-safe fields only. An
unauthenticated request MUST get 401 and a non-operator (agent) cert MUST get 403.

#### Scenario: An operator reads peer alerts and overdue agents
- **WHEN** an operator-role client requests the alerts and overdue endpoints
- **THEN** it receives the recent peer alerts and the overdue agents as JSON

#### Scenario: A non-operator is refused
- **WHEN** an agent-role client or an unauthenticated client requests those endpoints
- **THEN** it is refused (403 for the wrong role, 401 for no client certificate)
