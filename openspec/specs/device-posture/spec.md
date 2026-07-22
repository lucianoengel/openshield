# device-posture Specification

## Purpose
The endpoint device-posture producer: it reports what the endpoint can honestly observe about its device state (agent presence, disk encryption, patch tier), signs the report so the gateway can verify it, and publishes it on the posture channel — giving the device-posture tamper-lockout real data. Posture is self-reported (only as trustworthy as the reporter); hardware attestation is a separate hardening.

## Requirements

### Requirement: The endpoint reports honest, signed device posture
The producer MUST report device posture as what it can actually observe — the agent's presence, whether disk encryption is observed, and a patch tier — never asserting a compliance it did not verify. It MUST publish the report signed so the gateway can verify it against the trusted posture key, with the report's subject bound to the reporting agent. A report signed with an untrusted key MUST be rejected by the gateway and not applied.

#### Scenario: A signed posture report is verified and a forged one is not
- **WHEN** the producer builds and the gateway receives a posture report
- **THEN** a validly-signed report is applied to the posture store, and a wrong-key report is rejected and not applied
