## ADDED Requirements

### Requirement: The public-key chain is persisted with the entries it authenticates
The epoch public-key chain MUST be stored durably alongside the entries, not held only in the
signing process. Each epoch's index, public key, and predecessor signature are recorded; the
private key is never written.

A forward-secure scheme whose public material lives only in the writer's memory provides no
verifiable forward security: a second process cannot verify, and a restart orphans every entry
signed under a key the new process did not generate. Persisting the chain is what makes the
"verification requires no secret" property true of the system and not merely of the algorithm.

#### Scenario: A process that never held the signer can verify
- **WHEN** the ledger is opened by a process constructed with no signer and no private key
- **THEN** it loads the stored public-key chain and verifies an untampered ledger successfully
- **AND** a test verifies through a code path that holds no `*Signer`, so a regression that
  reached back into an in-memory signer would fail to compile

#### Scenario: The chain survives a restart with a fresh signer
- **WHEN** entries are written, the process exits, and a new process opens the same database
- **THEN** verification of the pre-restart entries still succeeds against the stored chain
- **AND** the test uses a DIFFERENT signer instance after the restart, because reusing the
  original signer would hide exactly the orphaning this requirement exists to prevent

#### Scenario: An entry can never reference an unstored epoch
- **WHEN** an entry is appended under a newly evolved epoch
- **THEN** the epoch's public-key row and the entry are committed in the same transaction
- **AND** the schema declares a foreign key from the entry's epoch to the stored epoch, so an
  entry referencing an absent epoch fails at write time rather than at audit time

#### Scenario: No private key is stored
- **WHEN** the persisted key-chain table's columns are inspected
- **THEN** no column holds private key material
- **AND** a test asserts the column set, so adding a private-key column fails the build

### Requirement: Verification can be pinned to an externally trusted anchor
Verification MUST accept a caller-supplied expected anchor. Given one, verification fails if the
stored chain does not begin at that anchor. Given none, verification checks internal consistency
and MUST report completeness as unverified, naming the absent anchor.

An anchor read from the same database that could have been rewritten attests to nothing. The
distinction between "the chain is internally consistent" and "the chain starts where an external
party says it must" is the difference between trusting the database to describe itself and not.
The caller, not the database, decides which was asked for.

#### Scenario: A wrong anchor is rejected
- **WHEN** verification is given an expected anchor that differs from the stored chain's first
  public key
- **THEN** verification fails with a reason naming the anchor mismatch
- **AND** it does not fall back to trusting the stored anchor

#### Scenario: Absent anchor degrades honestly, not silently
- **WHEN** verification is given no expected anchor
- **THEN** it verifies internal consistency and reports completeness as unverified
- **AND** the reported reason states that no external anchor was supplied, so a caller cannot
  read the result as a completeness guarantee
