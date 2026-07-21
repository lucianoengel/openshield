# provisioning delta

## ADDED Requirements

### Requirement: A separate interception CA distinct from the fleet CA
Provisioning MUST offer an interception CA generator that is distinct from the fleet mutual-TLS CA,
because an interception CA can sign a trusted certificate for any host and therefore impersonate any
site to every endpoint that trusts it — a far larger blast radius than fleet identity. The two MUST NOT
share a key or certificate.

#### Scenario: The interception CA is a distinct certificate authority
- **WHEN** an interception CA is generated
- **THEN** it is a CA certificate distinct from the fleet CA, usable to sign leaf certificates for
  arbitrary hosts, and its private key is the trust root whose custody secures interception
