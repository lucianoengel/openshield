# provisioning delta

## ADDED Requirements

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
