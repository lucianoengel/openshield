# provisioning Specification

## Purpose
Minimal issuance of the credentials the access-security stack needs — a local Ed25519 CA, role-tagged agent/operator certificates (Subject OU, per D58), and Curve25519 escrow keypairs (D59) — so mutual TLS, cert-role authorization and key escrow are deployable end to end rather than assumed issued out of band. It is a separate authority binary (not the read-only openshieldctl), and deliberately minimal: no revocation, rotation or HSM, with the CA and escrow private keys as documented trust roots (D16). See D60.
## Requirements
### Requirement: The tool issues a CA and role-tagged certs the security stack accepts
The provisioning tool MUST issue a self-signed CA and leaf certificates that verify against that CA,
carry the requested role (`agent` or `operator`) in the Subject Organizational Unit, and load through
the existing TLS loader — so mutual TLS (D55) and cert-role authorization (D58) work with provisioned
credentials, not only with hand-rolled ones.

A leaf certificate carries serverAuth and clientAuth usage and the caller-supplied SANs. An invalid
role is rejected. The tool writes private keys with restrictive permissions.

#### Scenario: A provisioned operator cert authorizes for view; an agent cert does not
- **WHEN** the tool issues a CA, an `operator`-role cert and an `agent`-role cert, and they front a
  mutual-TLS control plane
- **THEN** the operator cert is authorized on the view endpoint and the agent cert is refused `403`
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
