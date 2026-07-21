# enforcement delta

## ADDED Requirements

### Requirement: The encrypt-local action renders a flagged file unreadable in place
The engine MUST be able to dispatch `ENCRYPT_LOCAL` to an enforcer that replaces the flagged file's
contents with an authenticated ciphertext in place, so the file is genuinely unreadable without the
key — not merely relocated or renamed.

Encryption uses AES-256-GCM with a fresh per-file nonce, written atomically so a crash leaves either
the original or the fully-encrypted file. It is CONTAINMENT after detection, not prevention (the file
was already read to be classified), and its protection depends on key custody: an on-host key
defends against a stolen disk or a different user, not against the agent user or host root (D16).

#### Scenario: An encrypted file is unreadable without the key but recovers with it
- **WHEN** the encrypt-local enforcer encrypts a target file
- **THEN** the on-disk bytes differ from the plaintext and cannot be recovered with a wrong key
- **AND** a test decrypts with the correct key and recovers the exact original bytes

#### Scenario: Re-encrypting an already-encrypted file is idempotent
- **WHEN** the enforcer is applied to a file it has already encrypted
- **THEN** the file is not double-encrypted or corrupted and still recovers to the original plaintext
- **AND** a test asserts a second enforcement leaves the file recoverable

#### Scenario: No target is an error, never a silent no-op
- **WHEN** the enforcer is asked to encrypt with an empty target
- **THEN** it returns an error rather than reporting success
- **AND** a test asserts the empty-target error

### Requirement: A policy deciding encrypt-local routes to the enforcer and is audited
The engine MUST route an `ENCRYPT_LOCAL` Decision to a registered encrypt-local enforcer, encrypt the
target on disk, and audit the enforcement outcome, so enforcement is never silent (D14).

#### Scenario: Encrypt-local flows decision to encrypted file, audited
- **WHEN** a policy decides `ENCRYPT_LOCAL` for an event whose file is on disk and the encrypt-local
  enforcer is registered
- **THEN** the engine records the Decision, encrypts the file in place, and appends an enforcement
  outcome to the audit ledger
- **AND** an end-to-end test asserts the file is encrypted on disk and the outcome is recorded
