

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
