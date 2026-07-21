# network-gateway delta

## ADDED Requirements

### Requirement: A verified client identity resolves into the Zero-Trust context
The gateway MUST resolve a verified client certificate into a pseudonymous identity and an
authorization role in the pipeline context, replacing the hashed source address as the subject. The raw
identity MUST be pseudonymised one-way at the boundary and never enter the pipeline. A certificate that
is not a client certificate MUST be rejected as an identity. Device posture MUST remain absent (a
separate producer), so a cert-authenticated but unattested device still fails closed under the identity
context policy.

#### Scenario: A client certificate yields a pseudonymous subject and role
- **WHEN** a valid client certificate is resolved
- **THEN** the context carries a pseudonymous subject (not the raw identity) and the certificate's group
  as the role, with device posture marked absent

#### Scenario: A non-client certificate is rejected
- **WHEN** an agent or operator certificate is presented as a client identity
- **THEN** it is rejected
