# device-posture Specification

## Purpose
The endpoint device-posture producer: it reports what the endpoint can honestly observe about its device state (agent presence, disk encryption, patch tier), signs the report so the gateway can verify it, and publishes it on the posture channel — giving the device-posture tamper-lockout real data. Posture is self-reported (only as trustworthy as the reporter); hardware attestation is a separate hardening.

## Requirements

### Requirement: The endpoint reports honest, signed device posture
The producer MUST report device posture as what it can actually observe — the agent's presence, whether disk encryption is observed, and a patch tier — never asserting a compliance it did not verify. It MUST publish the report signed so the gateway can verify it against the trusted posture key, with the report's subject bound to the reporting agent. A report signed with an untrusted key MUST be rejected by the gateway and not applied.

#### Scenario: A signed posture report is verified and a forged one is not
- **WHEN** the producer builds and the gateway receives a posture report
- **THEN** a validly-signed report is applied to the posture store, and a wrong-key report is rejected and not applied

### Requirement: Posture is verified against the reporting agent's own key
The gateway MUST verify a signed device-posture update against the enrolled key of the update's own
subject (the reporting agent), so an update is applied for a subject only if it verifies against that
subject's own key. An agent MUST NOT be able to publish a posture for a different subject, an update
for an unenrolled subject MUST be rejected, and an unsigned or malformed update MUST be rejected. A
rejected update MUST be dropped and counted, never applied.

#### Scenario: An agent cannot forge another agent's posture
- **WHEN** an agent signs a compliant posture update whose subject is a different enrolled agent, and separately reports its own posture
- **THEN** the update for the other agent is rejected (it does not verify against that agent's key) while the agent's own posture is applied, and an update for an unenrolled subject or an unsigned update is rejected
