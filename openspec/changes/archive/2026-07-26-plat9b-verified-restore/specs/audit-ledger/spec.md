## ADDED Requirements

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
