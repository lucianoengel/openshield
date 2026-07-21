# network-gateway delta

## ADDED Requirements

### Requirement: The gateway applies only signed, verified risk and posture updates
The gateway MUST verify the Ed25519 signature of every published risk and device-posture
update against a trusted publisher key BEFORE applying it — risk against the control-plane
key, posture against the posture-publisher key — and MUST reject and count any update that is
unsigned, tampered, wrong-key, or malformed, never applying it. A channel with no configured
trusted key MUST NOT be subscribed, so an unsigned update is never applied. Verification MUST
occur before the inner update is parsed.

#### Scenario: A forged risk or posture update cannot change the store
- **WHEN** the gateway receives risk and posture updates
- **THEN** a validly-signed update is applied, and an unsigned, wrong-key, or tampered update is rejected and counted while the legitimate value stands
