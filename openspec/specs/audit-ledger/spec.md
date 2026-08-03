

## Purpose

The evidentiary record: a hash-chained, forward-secure append-only ledger in Postgres, where each entry
commits to its predecessor and signing keys evolve forward so an attacker who takes the host cannot
rewrite what happened before they arrived. Verification needs no secret, is pinnable to an external
witness anchor, and REPORTS THE BOUNDARY OF WHAT IT PROVES — completeness only through the last anchor.
The claim is tamper-EVIDENT, never tamper-proof, and the compromise window is stated where operators
see it. Also covers backup, rehearsed restore, and the retention purge's legal-hold exemption.

## Requirements

### Requirement: A restore is not verified until its completeness is anchor-proven

Restore verification SHALL require an external witness key and SHALL NOT report success without
anchor-proven completeness. A truncated ledger is internally consistent — it hashes perfectly and simply
stops early — so chain verification alone cannot detect the most likely way a restore loses evidence.

#### Scenario: A restore without a witness key is not reported as verified
- **WHEN** restore verification runs with no witness key
- **THEN** it fails rather than degrading to an unverified success

#### Scenario: A consistent but unanchored ledger is not reported as verified
- **WHEN** the chain is consistent but no anchor witnesses it
- **THEN** verification does not report success

#### Scenario: An anchored, consistent ledger is reported as verified
- **WHEN** the chain is consistent and an anchor witnesses it
- **THEN** verification reports success

### Requirement: The tail an anchor does not cover is reported

Verification SHALL report how much of the ledger lies beyond the highest anchored sequence. Completeness
is proven only to that point, and entries after it can be truncated undetectably — so a bare "consistent"
must not be allowed to imply the whole ledger survived.

#### Scenario: Entries beyond the anchor are stated
- **WHEN** the ledger extends past its highest anchored sequence
- **THEN** the report states how many entries are not covered

### Requirement: The three outcomes are distinguishable

Verification SHALL distinguish verified, tampered-or-truncated, and cannot-determine, so an operator can
tell "my evidence is intact" from "my evidence is damaged" from "I do not know".

#### Scenario: Each outcome has its own exit status
- **WHEN** verification completes
- **THEN** its exit status identifies which of the three outcomes occurred

### Requirement: The ledger can be backed up and the restore rehearsed
The system SHALL provide a command that backs up the system of record and one that REHEARSES the restore,
and the drill SHALL NOT report success unless the restored ledger re-verifies against its anchors.

Every tamper-evidence claim this product makes rests on the ledger, and none of it survives a disk
failure if the backup procedure is a package nobody can run — which is what `internal/backup` was until
D315: `DumpArgs`, `Script` and `DrillSteps` had no caller. A control that cannot survive its own
infrastructure failing has an unexamined single point of failure.

A byte-perfect `pg_restore` that produces an unverifiable ledger is a FAILED restore: the bytes came back
and the evidence did not. A drill must therefore be refused without a witness key — without an anchor to
check against, TRUNCATION is undetectable, and truncation is the most likely way a restore loses evidence.

#### Scenario: A backup is taken from a running deployment
- **WHEN** an operator runs the backup against a live database
- **THEN** a non-empty dump file is produced

#### Scenario: A drill without a witness is refused before touching the database
- **WHEN** a restore drill is requested with no witness key
- **THEN** it is refused, the message names the witness as what is missing, and no restore is attempted
- **AND** refusing afterwards would mean the system of record had already been replaced with something
  the drill cannot vouch for

#### Scenario: The rendered drill script fails closed and verifies last
- **WHEN** the drill is rendered as a shell script
- **THEN** it sets `-euo pipefail` and runs verification AFTER the restore
- **AND** without those, a failed restore is followed by a verification of whatever was already in the
  database, which can pass — a green drill over a restore that never happened

### Requirement: ENCRYPT_LOCAL is reversible end to end
A file encrypted by the running engine SHALL be recoverable by the shipped recovery command, in both
symmetric and escrow modes, and recovery SHALL never overwrite an existing file.

D293 found the encrypting half shipped with nothing able to decrypt — a containment action that, to the
person whose file it was, is indistinguishable from destroying it. The recovery command fixed that, and
then NEITHER HALF was exercised against a running engine: what was proven was that a package can encrypt
and a command can decrypt, not that the file the engine produces is the file the tool accepts. That gap
is where a format or mode mismatch lives, and it would surface for the first time on the day an operator
actually needed the data.

#### Scenario: A symmetrically encrypted file round-trips
- **WHEN** the engine encrypts a flagged file and the operator recovers it with the endpoint's key
- **THEN** the plaintext is reproduced exactly and the ciphertext is left untouched

#### Scenario: An escrow blob cannot be opened by the endpoint
- **WHEN** an escrow-encrypted file is offered the endpoint's own public key
- **THEN** recovery refuses and NAMES escrow as what is needed, rather than failing as a generic
  decryption error that reads identically to "your key is wrong"
- **AND** the off-endpoint keypair DOES recover it, or the scenario would pass against a build that
  cannot decrypt escrow blobs at all — which is the state D293 found

#### Scenario: Recovery refuses to overwrite
- **WHEN** recovery is pointed at an output path that already exists
- **THEN** it refuses before decrypting, naming the clobber, and the existing file is untouched
- **AND** the scenario uses a GENUINELY RECOVERABLE blob: with a corrupt one, removing the guard still
  fails at decryption and writes nothing, so the test would pass against the mutation

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-ledger -->

### Requirement: Core does not depend on a database driver
`internal/core` MUST NOT import a database driver. The ledger is an interface in core,
implemented outside it.

Same reasoning as the transport boundary: the endpoint pipeline is in-process and synchronous,
and a storage dependency inside core would invite blocking work into the permission window.

#### Scenario: Core has no database dependency
- **WHEN** CI computes the dependency graph of `internal/core`
- **THEN** it contains no database driver
- **AND** the check fails the build rather than warning

<!-- restored from 2026-07-20-add-audit-ledger -->

### Requirement: A failed append is never silent
If an entry cannot be appended, the caller MUST receive an error. The system SHALL NOT continue
as though the Decision were recorded.

An unrecorded Decision in an observe-only product is indistinguishable from an event that never
occurred, which is the failure mode the whole ledger exists to prevent.

#### Scenario: Append failure surfaces
- **WHEN** the database is unreachable and an append is attempted
- **THEN** the caller receives an error naming the condition
- **AND** no code path discards the entry without returning an error

<!-- restored from 2026-07-20-add-audit-ledger -->

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

<!-- restored from 2026-07-20-add-audit-timeline-cli -->

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

<!-- restored from 2026-07-20-add-audit-timeline-cli -->

### Requirement: A witnessed anchor attests to the ledger head
The ledger MUST support a witness-signed anchor recording a `(sequence, hash)` checkpoint, signed
by a key in a different trust domain than the ledger signer. Verifying an anchor MUST require only
public material.

An anchor the agent could forge proves nothing, because the agent is the party that might rewrite
the log. The witness signature — from a domain the deployer does not control — is what makes an
anchor evidence rather than decoration. Because the chain is linear, a checkpoint of the head hash
attests to the whole prefix without an inclusion proof.

#### Scenario: An anchor verifies with the witness public key alone
- **WHEN** a witness anchors the current head and the anchor is verified with the witness public key
- **THEN** verification succeeds using no secret
- **AND** an anchor signed by the wrong key fails

<!-- restored from 2026-07-21-add-external-anchoring -->

### Requirement: Verification proves completeness only through the last anchor
Given valid anchors, verification MUST confirm each anchor's `(sequence, hash)` matches the chain,
report the highest witnessed sequence as `AnchoredThrough`, and mark completeness ANCHORED only
when the whole chain is witnessed — leaving the tail after the last anchor UNVERIFIED.

Completeness is provable only where a witness attests to it. The prefix up to the last anchor
cannot be truncated undetectably; everything after it still can. A verifier MUST be told that
exact boundary rather than a single yes/no, or it will mistake "the witnessed prefix is complete"
for "nothing was removed".

#### Scenario: A partially-anchored chain reports the boundary
- **WHEN** a chain has an anchor at sequence N and further un-anchored entries after N
- **THEN** verification reports `AnchoredThrough = N` and completeness UNVERIFIED overall
- **AND** a test asserts the prefix is reported anchored and the tail unverified

#### Scenario: A fully-anchored chain is complete
- **WHEN** an anchor covers the last entry
- **THEN** completeness is ANCHORED

<!-- restored from 2026-07-21-add-external-anchoring -->

### Requirement: Truncation of witnessed history is detected
If the chain is truncated or rebuilt shorter than a valid anchor's sequence, verification MUST
fail, naming the anchor whose checkpoint is no longer satisfied.

This is the property anchoring exists to add: destroying WITNESSED history is caught. Destroying
unwitnessed history — the tail since the last anchor — still is not, and that residual window
equals the anchor interval and MUST be documented where the interval is configured.

#### Scenario: A chain rebuilt shorter than an anchor fails
- **WHEN** an anchor attests sequence N but the chain now ends before N (or entry N's hash differs)
- **THEN** verification fails and names the violated anchor
- **AND** a test rebuilds a shorter chain past an anchor and asserts detection

#### Scenario: No-anchor behaviour is unchanged
- **WHEN** verification runs with no anchors
- **THEN** it behaves exactly as before — completeness UNVERIFIED — so anchoring is purely additive

<!-- restored from 2026-07-21-add-external-anchoring -->

### Requirement: The ledger signer resumes its chain across a restart
The signer's CURRENT state MUST be exportable and reloadable such that a new process reconstructs an
identical signer and continues the SAME chain — the reloaded signer's anchor matches the stored
chain, so writing resumes rather than forking or being refused. Only the current epoch's private key
is persisted; destroyed keys MUST NOT be.

An append-only evidentiary log that cannot continue after a reboot is a real hole. The public chain
is persisted already; the missing piece is the current private key. Persisting only the current
epoch keeps forward security intact — that epoch is already the compromise window, and earlier keys
were destroyed and are absent.

#### Scenario: A reloaded signer continues the chain
- **WHEN** entries are appended, the signer is exported, a fresh process loads it, reopens the
  ledger, and appends more
- **THEN** the reopen succeeds (the anchor matches) and the full chain verifies continuously
- **AND** a test drives export→reload→resume and asserts one continuous verifiable chain

#### Scenario: A corrupt or mismatched export fails to load
- **WHEN** a signer blob is corrupted, or its private key does not match the chain's current epoch
- **THEN** loading returns an error rather than a signer that signs under a key the chain omits

#### Scenario: Destroyed keys are not in the export
- **WHEN** an exported signer that has evolved is inspected
- **THEN** it contains only the current epoch's private key, not any prior epoch's

<!-- restored from 2026-07-21-add-signer-persistence -->

### Requirement: The ledger is append-only at the database level
The audit ledger MUST reject, at the database, any DELETE of an entry and any UPDATE that changes an
integrity column (sequence, appended_at, prev_hash, hash, sig, key_epoch, retention_class,
context_version), so a leaked connection string cannot rewrite or truncate history through ordinary
SQL — tamper-resistance is not left solely to a read-time verification.

The D36 retention tombstone MUST still succeed, because it mutates only content columns and sets
tombstoned_at. Resurrecting a tombstoned entry (clearing tombstoned_at) MUST be rejected. This is
defence in depth: a table owner who disables the control can still tamper, and that is caught by
Verify() and external anchoring (D38), which remain the guarantee against a determined adversary.

#### Scenario: A leaked connection cannot delete or rewrite an entry
- **WHEN** the app role attempts to DELETE an audit entry or UPDATE its hash
- **THEN** the database rejects both
- **AND** a test asserts the delete and the hash update both error

#### Scenario: Retention tombstoning still works
- **WHEN** retention tombstones an expired entry (nulls content columns, sets tombstoned_at)
- **THEN** the update succeeds and the entry's skeleton is unchanged
- **AND** a test asserts the tombstone succeeds and the chain remains verifiable

#### Scenario: Verify still catches a tamper that bypasses the control
- **WHEN** an adversary bypasses the database control (disables the trigger, e.g. as a table owner)
  and modifies or deletes an entry
- **THEN** Verify() still detects and locates the tampering
- **AND** a test performs the bypass, tampers, and asserts Verify() reports it

<!-- restored from 2026-07-21-append-only-ledger -->

### Requirement: External anchoring is runnable and schedulable
The system MUST provide a runnable path that witnesses the ledger head with a persistent, externally
held witness key and stores the anchor, so a deployment can move off permanent `Completeness:
UNVERIFIED` — the anchoring mechanism (T-019/D38) must actually run, not exist only as a library call.

The witness process MUST hold only the witness key, never the ledger signer (it attests, it cannot
append). A witness key MUST be persistable and reloadable, so anchors are witnessed under a stable key
a verifier can check. Witness custody determines the guarantee (a key the deployer controls attests to
little), and the undetectable-loss window is the interval between anchors.

#### Scenario: Anchoring moves completeness off UNVERIFIED
- **WHEN** a witness reconstructed from a saved key anchors the current head and verification is run
  with that witness's public key
- **THEN** verification reports the range as anchored, not UNVERIFIED
- **AND** a test asserts the completeness transition, and the witness process opens the ledger without
  the ledger signer

#### Scenario: An auditor verifies completeness against the witness public key
- **WHEN** an auditor runs verification supplying the witness public key
- **THEN** the anchored range is reported; without the witness key, the honest UNVERIFIED degraded
  mode is reported unchanged
- **AND** the verification surface remains signer-less (it cannot produce entries or anchors)

<!-- restored from 2026-07-21-operational-anchoring -->

### Requirement: The retention purge never erases a subject under an active legal hold
The retention purge MUST NOT tombstone an entry whose subject is under an active legal hold,
regardless of the entry's retention class or age — because an entry's retention class is
immutable, a hold recorded after the entry was written is the only way to protect it. Releasing
the hold MUST restore normal purge eligibility.

#### Scenario: A legal hold overrides routine purge
- **WHEN** the purge runs over aged routine entries and one subject is under an active legal hold
- **THEN** the held subject's evidence survives while an unheld subject's is tombstoned, and releasing the hold lets a later purge tombstone it

<!-- restored from 2026-07-21-sec5-purge-respects-legal-hold -->

### Requirement: The application runs under a non-owner role that cannot weaken the append-only guard
The ledger MUST support running the application under a non-owner database role that can insert
entries and perform the permitted tombstone update but CANNOT alter the table, disable the
append-only trigger, delete, drop the table, or escalate to the owner. Migrations MUST be an
owner operation; the application MUST be able to open an already-migrated database without owner
rights, skipping migration via a read-only check.

#### Scenario: A non-owner app can append but cannot weaken the guard
- **WHEN** the application runs under a non-owner writer role
- **THEN** it can append entries but cannot disable the append-only trigger, delete, drop the table, or become the owner

<!-- restored from 2026-07-21-sec6-nonowner-ledger-role -->

### Requirement: A ledger that was anchored but never written to can be reopened

Opening the ledger for writing SHALL succeed when the key-epoch anchor is stored and no entries exist
yet, continuing from the genesis hash exactly as a fresh database does.

The anchor epoch is persisted when a process first opens the ledger; the first ENTRY is written
whenever a decision is first made, which may be much later or never. Between those two moments the
database holds an epoch and no entries, and that is an ordinary state: install, start, notice a wrong
setting, restart. It is also every host whose enforcement was disabled fleet-wide before it decided
anything.

Refusing to reopen there is permanent and self-inflicted — every subsequent start hits the same
branch, so the process can never write the entry that would let it start, and recovery means deleting
a row by hand from an append-only audit store.

The anchor check SHALL still run first: an empty ledger is a reason to continue from genesis, never a
reason to admit a signer that does not own the stored anchor.

#### Scenario: Reopening after a restart with no entries
- **WHEN** a process opens the ledger, writes nothing, exits, and a new process opens it with the same
  signer
- **THEN** the open succeeds, and the first entry written afterwards is sequence 0 committing to the
  genesis hash

#### Scenario: An empty ledger still refuses a foreign signer
- **WHEN** a signer that does not own the stored anchor opens a ledger holding an anchor and no entries
- **THEN** the open is refused, because two signers on one chain is the fork the anchor check prevents

<!-- from secb-persistent-replay-bound -->
