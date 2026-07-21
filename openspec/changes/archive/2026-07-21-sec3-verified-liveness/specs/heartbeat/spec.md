# heartbeat delta

## MODIFIED Requirements

### Requirement: Liveness counts only verified telemetry over the enrolled roster
The dead-man's-switch MUST derive an agent's last-seen from VERIFIED telemetry only, so an
unsigned publisher cannot keep a dead or compromised agent alive, and MUST evaluate liveness over
the enrolled, non-revoked roster so an enrolled-but-silent (or purged) agent still surfaces as
overdue. A last-seen lookup MUST distinguish a database error from agent absence — a query error
MUST be returned as an error, never masqueraded as "agent unknown".

#### Scenario: An unsigned publisher cannot mask a silent agent
- **WHEN** the control plane evaluates liveness
- **THEN** an agent seen only via unverified telemetry is overdue, an enrolled-but-never-seen agent is overdue, a verified-fresh agent is not, and a database error surfaces as an error rather than absence
