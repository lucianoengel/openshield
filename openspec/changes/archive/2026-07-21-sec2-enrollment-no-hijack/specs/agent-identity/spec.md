# agent-identity delta

## MODIFIED Requirements

### Requirement: Enrollment records a new identity and cannot overwrite or un-revoke
Enrollment MUST record a NEW agent identity and MUST refuse, without consuming the token, any
enrollment for an agent id that already exists — it MUST NOT overwrite an existing public key
or clear a revocation. Re-enrollment of an existing id MUST be an explicit operator action
(revoke or delete the old identity first). A revoked agent MUST stay revoked against any
fresh enrollment token.

#### Scenario: A fresh token cannot hijack or un-revoke an agent
- **WHEN** a token is used to enroll an agent id that already exists or is revoked
- **THEN** enrollment is refused, the existing key still verifies, and a revoked agent stays revoked
