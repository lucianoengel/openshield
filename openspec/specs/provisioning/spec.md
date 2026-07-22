# provisioning Specification

## Purpose
Minimal issuance of the credentials the access-security stack needs — a local Ed25519 CA, role-tagged agent/operator certificates (Subject OU, per D58), and Curve25519 escrow keypairs (D59) — so mutual TLS, cert-role authorization and key escrow are deployable end to end rather than assumed issued out of band. It is a separate authority binary (not the read-only openshieldctl), and deliberately minimal: no revocation, rotation or HSM, with the CA and escrow private keys as documented trust roots (D16). See D60.
## Requirements
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
- **WHEN** the tool issues a CA and a leaf cert
- **THEN** the leaf verifies against the CA by x509 verification and loads via the TLS config loader
  without error
- **AND** an invalid role is rejected rather than issued

### Requirement: The tool generates escrow keypairs the enforcer accepts
The provisioning tool MUST generate a Curve25519 escrow keypair whose public key the escrow enforcer
loads and whose private key recovers what the enforcer seals, so key escrow (D59) is deployable.

The public key is written for endpoints (loaded by the escrow enforcer); the private key is written
for the off-endpoint holder (used for recovery). A wrong private key does not recover.

#### Scenario: A provisioned escrow keypair round-trips
- **WHEN** the tool generates an escrow keypair, the enforcer seals a file to the public key, and the
  private key is used to recover it
- **THEN** the exact original bytes are recovered, and a different private key fails
- **AND** a test asserts both outcomes

### Requirement: Provisioning is minimal and its trust roots are documented, not overclaimed
The provisioning tool MUST be documented as minimal issuance for dev and small fleets, not a full PKI,
so its limits are explicit: no revocation, no rotation automation, and the CA and escrow private keys
are the trust roots whose custody (D16) determines the whole scheme's security.

#### Scenario: Docs state the CA-key and escrow-key custody boundary
- **WHEN** the provisioning capability is described
- **THEN** the docs state that whoever holds the CA private key can mint any cert (including an
  operator cert) and whoever holds the escrow private key can read every escrowed file
- **AND** no claim of revocation, rotation, or production-PKI equivalence is made

### Requirement: The tool generates witness keypairs
The provisioning tool MUST generate a witness keypair — the private key for the witness host and the
public key for verifiers — so external anchoring can be provisioned like the other credentials.

The private key is written for the witness host (held in a trust domain the deployer does not
control); the public key is distributed to verifiers.

#### Scenario: A provisioned witness keypair anchors and verifies
- **WHEN** the tool generates a witness keypair, the witness tool anchors the head with the private
  key, and verification uses the public key
- **THEN** the anchor verifies and the range is reported anchored
- **AND** a test asserts the round trip


### Requirement: A separate interception CA distinct from the fleet CA
Provisioning MUST offer an interception CA generator that is distinct from the fleet mutual-TLS CA,
because an interception CA can sign a trusted certificate for any host and therefore impersonate any
site to every endpoint that trusts it — a far larger blast radius than fleet identity. The two MUST NOT
share a key or certificate.

#### Scenario: The interception CA is a distinct certificate authority
- **WHEN** an interception CA is generated
- **THEN** it is a CA certificate distinct from the fleet CA, usable to sign leaf certificates for
  arbitrary hosts, and its private key is the trust root whose custody secures interception

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

### Requirement: Client-role certificates are issued distinctly from agent and operator
Provisioning MUST issue a client-role certificate through a path distinct from the agent/operator
issuance, carrying a client-role marker and an authorization group, so a client certificate can never
be mistaken for an agent or operator certificate at the role gate. The agent/operator issuance MUST be
unchanged.

#### Scenario: A client certificate carries the client role and a group
- **WHEN** a client certificate is issued for an identity and a group
- **THEN** it is signed by the CA, marked with the client role, and carries the group, and it is not an
  agent or operator certificate

### Requirement: A RoleClient device certificate binds to the enrolled agent identity

A client-role certificate issued to authenticate a DEVICE at the Zero-Trust access proxy MUST carry a
common name equal to the device's enrolled agent identity, so that the pseudonym the proxy derives
from the certificate equals the canonical pseudonym the device's posture producer publishes under.
The client-role distinctness and authorization-group markers are unchanged; this constrains
only the common name for the device-authentication case, and MUST NOT change agent or operator
issuance. The raw identity is still pseudonymised one-way at the boundary (D23) — the constraint is
that both sides derive the SAME pseudonym from the SAME identity, not that the identity is exposed.

#### Scenario: A device client certificate resolves to the agent's posture subject

- **WHEN** a client-role certificate is issued for a device with its common name set to the enrolled
  agent identity, and that certificate is resolved at the access proxy
- **THEN** the pseudonymous subject the proxy derives equals the canonical pseudonym the posture
  producer publishes under for that same agent identity, so the device's published posture is found
