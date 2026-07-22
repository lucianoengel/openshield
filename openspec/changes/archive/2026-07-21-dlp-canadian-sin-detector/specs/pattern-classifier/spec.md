# pattern-classifier (delta)

## ADDED Requirements

### Requirement: The classifier detects Canadian SINs by grouping and Luhn checksum
The classifier MUST detect a Canadian Social Insurance Number by validating a conventionally
grouped candidate (NNN-NNN-NNN, hyphen or space separated) against the Luhn checksum, and MUST NOT
report a grouped number that fails Luhn nor a bare (ungrouped) 9-digit run. A SIN hit MUST carry a
confidence reflecting Luhn-over-a-distinctive-grouping — strong, and near the credit-card Luhn.

#### Scenario: A grouped Luhn-valid SIN is detected and look-alikes are not
- **WHEN** the classifier scans text containing grouped SINs and 9-digit look-alikes
- **THEN** the grouped Luhn-valid numbers are detected while a Luhn-off-by-one, a grouped-but-invalid number, and a bare ungrouped run read clean
