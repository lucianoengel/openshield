# audit-ledger Specification

## Purpose
TBD - created by archiving change add-audit-ledger. Update Purpose after archive.
## Requirements
### Requirement: Every entry commits to its predecessor
Each ledger entry MUST contain a hash computed over its own content and the hash of the entry
before it. The first entry commits to a genesis value that is recorded.

A chain makes an edit detectable: changing any entry invalidates every hash after it, so an
attacker must rewrite the tail rather than a single row.

#### Scenario: Editing an entry is detected
- **WHEN** an entry's content is modified directly in the database
- **THEN** verification fails
- **AND** the failure names the first entry whose hash does not match, so the tampering is
  located rather than merely reported

#### Scenario: Deleting an entry is detected
- **WHEN** an entry is deleted from the middle of the chain
- **THEN** verification fails at the following entry

### Requirement: Signing keys evolve forward and prior private keys are destroyed
The ledger MUST sign entries with an evolving asymmetric keypair, publishing each successor
public key signed by its predecessor, and MUST destroy each private key when it evolves — so
that key material recovered at time T cannot produce a valid signature for any entry written
before T.

The hash chain alone only forces an attacker to rewrite the tail. Key evolution is what makes
the tail they can rewrite begin at the moment of compromise.

#### Scenario: Compromised key material cannot forge earlier entries
- **WHEN** an attacker obtains **everything the agent process holds** at entry N — the current
  private key, the public-key chain, and any file the agent can read
- **THEN** they can produce valid signatures for entries N and later
- **AND** they cannot produce a valid signature for any entry before N
- **AND** the test MUST model the attacker taking the whole process state, not a convenient
  subset: an earlier version of this test handed the attacker a derived key while the
  implementation retained a master seed, so it passed against an implementation that provided
  no forward integrity at all

#### Scenario: The prior private key is unrecoverable after evolution
- **WHEN** the keypair evolves
- **THEN** the prior private key is not derivable from the current private key, the public-key
  chain, or any material the agent retains

### Requirement: Verification requires no secret
Verifying the ledger MUST require only public material — the anchor public key and the chain of
signed successor public keys. No secret capable of producing valid entries may be required to
verify.

A symmetric scheme fails this: verification needs the seed, and the seed forges. That would make
the only party able to verify the log the same party able to fake it — concentrating fleet-wide
forgery in the control plane, preventing an endpoint from verifying its own log, and collapsing
entirely on a single-node air-gapped deployment where no second trust domain exists.

#### Scenario: An independent party verifies without any forging capability
- **WHEN** a verifier is given the ledger and the anchor public key, and nothing else
- **THEN** verification succeeds on an untampered chain and fails on a tampered one
- **AND** a test performs verification with no access to any private key, so a regression that
  reintroduced a secret-dependent path would fail to compile or run

#### Scenario: No forging key exists on the control plane
- **WHEN** the control plane's stored material for an agent is inspected
- **THEN** it contains no key capable of producing a valid ledger entry for that agent

### Requirement: The compromise window is the epoch and is stated where operators see it
Epoch length MUST be documented as a security parameter wherever an operator configures it,
because everything within the current epoch is forgeable by whoever compromises the host. Key
evolution may occur per epoch rather than per entry.

#### Scenario: Epoch length is documented as a security parameter
- **WHEN** the configuration surface for epoch length is read
- **THEN** it states that the epoch bounds how much recent history a host compromise can rewrite

#### Scenario: The key actually evolves during ordinary operation
- **WHEN** more entries are appended than one epoch admits
- **THEN** the signing key has evolved and later entries are signed by a different epoch key
- **AND** the chain still verifies across the epoch boundary, since entries signed by a
  destroyed key must remain valid against the published public-key chain
- **AND** the default epoch length is finite rather than unbounded: a key that never evolves
  provides no forward integrity at all, because the key that signed the first entry is still
  resident at the ten-thousandth

### Requirement: The tamper-evidence claim states what it does not cover
Documentation and any user-facing surface MUST describe the ledger as tamper-**evident** with
forward integrity, and MUST NOT describe it as tamper-proof.

An attacker holding root on the host can still suppress future entries, fabricate entries
forward from the moment of compromise, or destroy the log outright. Verification detects
alteration of the past; it cannot manufacture evidence that no longer exists.

#### Scenario: Destruction is reported honestly
- **WHEN** the ledger is truncated or deleted
- **THEN** verification reports that the chain is absent or incomplete
- **AND** does not report success

#### Scenario: No surface claims tamper-proofing
- **WHEN** the CI documentation check runs over claim surfaces
- **THEN** no unqualified use of "tamper-proof" is present

### Requirement: Verification reports the boundary of what it proves
Verification MUST report the range of entries it validated and the anchor state, so a caller
cannot mistake "the chain is internally consistent" for "nothing was removed".

Between external anchors (T-019), a root attacker can destroy the entire chain and rebuild a
shorter consistent one. Internal consistency is not evidence of completeness, and a verification
API that returns a bare boolean invites exactly that confusion.

#### Scenario: Verification distinguishes consistent from complete
- **WHEN** verification succeeds over a chain with no external anchor
- **THEN** the result states that completeness is unverified
- **AND** the result is not a bare boolean

### Requirement: Entries carry the fields later phases require
Each entry MUST record the Decision, its `context_version`, the pseudonymous subject, the
declared purpose, and a retention class, from the first migration onward.

The ledger is hash-chained, so adding a column later is not an ordinary migration: it changes
what is hashed and breaks continuity at the point of change. Columns that later phases require
must exist now, even unwritten. This is the same reasoning that put `context_version` on
`Decision` before any consumer existed.

#### Scenario: Retention and purpose are recordable from the first migration
- **WHEN** the initial migration is applied
- **THEN** columns exist for retention class, purpose, pseudonymous subject and context version
- **AND** a test asserts their presence, so a migration that omits them fails rather than
  deferring the cost to a chain break

### Requirement: Core does not depend on a database driver
`internal/core` MUST NOT import a database driver. The ledger is an interface in core,
implemented outside it.

Same reasoning as the transport boundary: the endpoint pipeline is in-process and synchronous,
and a storage dependency inside core would invite blocking work into the permission window.

#### Scenario: Core has no database dependency
- **WHEN** CI computes the dependency graph of `internal/core`
- **THEN** it contains no database driver
- **AND** the check fails the build rather than warning

### Requirement: A failed append is never silent
If an entry cannot be appended, the caller MUST receive an error. The system SHALL NOT continue
as though the Decision were recorded.

An unrecorded Decision in an observe-only product is indistinguishable from an event that never
occurred, which is the failure mode the whole ledger exists to prevent.

#### Scenario: Append failure surfaces
- **WHEN** the database is unreachable and an append is attempted
- **THEN** the caller receives an error naming the condition
- **AND** no code path discards the entry without returning an error

