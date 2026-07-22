## MODIFIED Requirements

### Requirement: The tool issues a CA and role-tagged certs the security stack accepts
The provisioning tool MUST issue a self-signed CA and leaf certificates that verify against that CA,
carry the requested role in the Subject Organizational Unit, and load through the existing TLS loader
— so mutual TLS (D55) and cert-role authorization (D58) work with provisioned credentials, not only
with hand-rolled ones. The tool MUST accept the operator-tier roles (`analyst`, `responder`, `admin`)
in addition to `agent` and `operator`, so a deployer can mint least-privilege operator certificates.

A leaf certificate carries serverAuth and clientAuth usage and the caller-supplied SANs. An invalid
role is rejected. The tool writes private keys with restrictive permissions.

#### Scenario: A provisioned operator cert authorizes for view; an agent cert does not
- **WHEN** the tool issues a CA, an `admin`-role cert and an `agent`-role cert, and they front a
  mutual-TLS control plane
- **THEN** the admin cert is authorized on the view endpoint and the agent cert is refused `403`
- **AND** a test drives the real role gate with the provisioned certs

#### Scenario: Issued certs verify against the CA and load through the TLS loader
- **WHEN** the tool issues a CA and a leaf cert for any accepted role (agent/operator/analyst/responder/admin)
- **THEN** the leaf verifies against the CA by x509 verification and loads via the TLS config loader
  without error
- **AND** an invalid role is rejected rather than issued
