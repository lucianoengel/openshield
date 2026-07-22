# device-posture (delta)

## ADDED Requirements

### Requirement: Posture is verified against the reporting agent's own key
The gateway MUST verify a signed device-posture update against the enrolled key of the update's own
subject (the reporting agent), so an update is applied for a subject only if it verifies against that
subject's own key. An agent MUST NOT be able to publish a posture for a different subject, an update
for an unenrolled subject MUST be rejected, and an unsigned or malformed update MUST be rejected. A
rejected update MUST be dropped and counted, never applied.

#### Scenario: An agent cannot forge another agent's posture
- **WHEN** an agent signs a compliant posture update whose subject is a different enrolled agent, and separately reports its own posture
- **THEN** the update for the other agent is rejected (it does not verify against that agent's key) while the agent's own posture is applied, and an update for an unenrolled subject or an unsigned update is rejected
