# provisioning delta

## ADDED Requirements

### Requirement: The interception CA revocation posture is documented in the minimal PKI
The interception CA's revocation and rotation posture MUST be stated, since the minimal PKI has no
CRL/OCSP: interception leaves are ephemeral and short-lived, so a leaked leaf self-limits by expiry
(the leaf TTL is the leaf-revocation mechanism); CA-level revocation is achieved by rotating to a new
CA or removing the CA configuration so interception falls back to tunneling; and removing a
compromised CA from endpoint trust stores is the endpoint's responsibility, outside the gateway.

#### Scenario: Leaf and CA revocation have stated mechanisms
- **WHEN** the interception PKI's revocation is documented
- **THEN** leaf revocation is the short leaf TTL, CA revocation is rotate-away or remove-to-tunnel, and
  endpoint trust-store removal is named as the endpoint's responsibility
