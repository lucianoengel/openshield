# network-gateway delta

## ADDED Requirements

### Requirement: The access proxy enriches decisions with published device posture, unattested devices fail closed
The gateway MUST subscribe to published device-posture updates and record each into a posture store, and
the access proxy MUST enrich each request's decision context with the connecting subject's posture. A
subject with published posture MUST carry it (marked present); a subject with NO published posture MUST
keep posture absent, so a policy requiring an attested device denies it (the tamper-lockout). A malformed
posture update MUST be rejected, not silently ignored.

#### Scenario: A compliant device is allowed and an unattested device is denied
- **WHEN** a policy requires an attested compliant device, and a subject has compliant posture published
- **THEN** it is allowed; and a subject with no published posture is denied
