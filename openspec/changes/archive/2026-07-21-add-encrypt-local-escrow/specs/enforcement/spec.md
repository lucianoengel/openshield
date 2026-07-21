# enforcement delta

## ADDED Requirements

### Requirement: Encrypt-local escrow mode seals so the endpoint cannot decrypt
The encrypt-local enforcer MUST support an escrow mode that seals a flagged file to a recipient PUBLIC
key such that the endpoint — holding only that public key — cannot decrypt it, so a fully-compromised
endpoint yields ciphertext it cannot open; recovery MUST require the recipient PRIVATE key held off
the endpoint.

Escrow uses Curve25519 anonymous sealed-box. Escrow blobs carry a distinct magic from symmetric
blobs so a blob is self-describing and recovery uses the right key. All D57 invariants hold: atomic
in-place replace, idempotent re-encryption, an empty target errors, and it is containment after
detection, not prevention. Escrow shifts trust to the private-key holder — it defends against
endpoint compromise, not against compromise of the escrow holder (whose key custody is D16).

#### Scenario: An escrow blob opens only with the private key
- **WHEN** the enforcer encrypts a file in escrow mode with a recipient public key
- **THEN** the on-disk blob cannot be decrypted with only the public key or the endpoint's material
- **AND** a test decrypts it with the recipient private key and recovers the exact original bytes, and
  a wrong private key fails

#### Scenario: Escrow and symmetric blobs do not cross
- **WHEN** a symmetric decrypt is attempted on an escrow blob (or vice versa)
- **THEN** it is rejected by the magic rather than silently mis-handled
- **AND** re-encrypting an already-encrypted file (either mode) is still an idempotent no-op

### Requirement: A policy deciding encrypt-local in escrow mode is audited
The engine MUST route an `ENCRYPT_LOCAL` Decision to a registered escrow-mode encrypt-local enforcer,
seal the target on disk so only the escrow private key recovers it, and audit the enforcement outcome
(never silent, D14).

#### Scenario: Escrow enforcement flows decision to sealed file, audited
- **WHEN** a policy decides `ENCRYPT_LOCAL` for an event whose file is on disk and an escrow-mode
  enforcer is registered
- **THEN** the engine records the Decision, seals the file to the recipient public key, and appends
  an enforcement outcome to the ledger
- **AND** an end-to-end test asserts the file recovers only with the escrow private key
