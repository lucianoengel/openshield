# policy-evaluation delta

## ADDED Requirements

### Requirement: Policy can decide identity-aware authorization, and absent posture fails closed
The policy input MUST expose the identity, role, and device posture (including the presence flag) as a
boundary-safe closed projection of the Context, so a policy can make identity-aware authorization
decisions. A policy MUST be able to deny access when device posture is absent (an untrusted or tampered
device), and to deny a device that is present but not compliant.

#### Scenario: A compliant identity is allowed and an untrusted device is denied
- **WHEN** an identity-aware policy evaluates a compliant device for an authorized role
- **THEN** it allows; and when the device reports no posture, or reports non-compliant, it denies
