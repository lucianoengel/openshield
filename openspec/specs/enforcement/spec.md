# enforcement Specification

## Purpose
Post-decision enforcement: the engine records a Decision then dispatches it to a registered enforcer that carries it out, auditing the outcome (failure high-severity). Observe-only is the default; enforcement CONTAINS after detection (quarantine, encrypt, revoke), it does not PREVENT the triggering access; inline blocking is deferred (T-002 budget).
## Requirements
### Requirement: A Decision is recorded before enforcement, and enforcement is audited
The engine MUST record a Decision before attempting enforcement, and MUST audit the enforcement
outcome — a failed enforcement is a high-severity audit event, never silence. With no enforcers
registered the engine MUST NOT enforce (observe-only default).

The audit must show what was decided even if enforcement fails or the machine dies mid-enforce, so
recording precedes enforcing. A silent enforcement failure is the quiet failure D14 forbids. And D1
keeps observe-only the default — enforcement is opt-in, per action.

#### Scenario: No enforcers means observe-only
- **WHEN** the engine processes an event with no enforcers registered
- **THEN** it records the Decision and enforces nothing
- **AND** a test asserts no enforcement occurred

#### Scenario: A matching enforcer carries out the Decision, audited
- **WHEN** a Decision with an enforceable action is produced and a registered enforcer advertises it
- **THEN** the Decision is recorded, the enforcer is invoked, and the enforcement outcome is audited
- **AND** a test asserts the order (recorded before enforced) and that both are in the ledger

#### Scenario: Enforcement failure is high-severity and audited
- **WHEN** an enforcer returns an error
- **THEN** a high-severity audit entry records the enforcement failure
- **AND** a test asserts the failure is recorded, not swallowed

### Requirement: Post-decision enforcement contains, it does not prevent
Documentation and any surface MUST describe enforcement as CONTAINMENT after detection (quarantine,
encrypt, revoke), not PREVENTION of the access that triggered it. Inline blocking within the
permission window is not provided.

The file was already read — that is how it was classified. Post-decision enforcement moves,
encrypts or revokes after the fact; it does not stop the open. Calling this "prevention" would be
the exact overclaim the threat model forbids (D16); inline blocking stays deferred because the
pipeline cannot complete in the permission window (T-002).

#### Scenario: No surface claims prevention
- **WHEN** enforcement is described
- **THEN** it is described as post-decision containment, defeatable by root, with inline blocking
  named as deferred and infeasible for classification-dependent decisions

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

