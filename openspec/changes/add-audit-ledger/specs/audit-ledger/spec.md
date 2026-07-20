## ADDED Requirements

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

### Requirement: The signing key is ratcheted forward and the old key destroyed
The ledger MUST evolve its signing key and destroy the previous key, so that a key recovered at
time T cannot produce a valid signature for any entry written before T.

Without this, forward integrity is not achieved: an attacker who compromises the host obtains
the current key and can rewrite the entire history consistently, chain and all. The hash chain
alone only forces them to rewrite the tail — key evolution is what makes the tail they can
rewrite start at the moment of compromise.

#### Scenario: A recovered key cannot forge earlier entries
- **WHEN** an attacker obtains the signing key in force at entry N
- **THEN** they can produce valid signatures for entries N and later
- **AND** they cannot produce a valid signature for any entry before N
- **AND** a test demonstrates this by attempting exactly that forgery with the later key

#### Scenario: The previous key is unrecoverable after ratcheting
- **WHEN** the key evolves
- **THEN** the prior key is not derivable from the current key or from any stored material

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
