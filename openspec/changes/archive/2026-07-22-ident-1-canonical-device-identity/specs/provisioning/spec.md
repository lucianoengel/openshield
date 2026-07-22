## ADDED Requirements

### Requirement: A RoleClient device certificate binds to the enrolled agent identity

A client-role certificate issued to authenticate a DEVICE at the Zero-Trust access proxy MUST carry a
common name equal to the device's enrolled agent identity, so that the pseudonym the proxy derives
from the certificate equals the canonical pseudonym the device's posture producer publishes under. The client-role distinctness and authorization-group markers are unchanged; this constrains
only the common name for the device-authentication case, and MUST NOT change agent or operator
issuance. The raw identity is still pseudonymised one-way at the boundary (D23) — the constraint is
that both sides derive the SAME pseudonym from the SAME identity, not that the identity is exposed.

#### Scenario: A device client certificate resolves to the agent's posture subject

- **WHEN** a client-role certificate is issued for a device with its common name set to the enrolled
  agent identity, and that certificate is resolved at the access proxy
- **THEN** the pseudonymous subject the proxy derives equals the canonical pseudonym the posture
  producer publishes under for that same agent identity, so the device's published posture is found
