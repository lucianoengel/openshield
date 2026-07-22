# pattern-classifier (delta)

## ADDED Requirements

### Requirement: The classifier detects US bank routing numbers by checksum and structure
The classifier MUST detect a US bank routing number (ABA) by validating a 9-digit candidate
against BOTH the ABA weighted mod-10 checksum AND the Federal Reserve routing-symbol leading-digit
range, and MUST NOT report a 9-digit run that fails either check. A routing-number hit MUST carry a
confidence between the checksumless structural detectors and the two-check-digit schemes, reflecting
that one checksum plus a range is stronger than a structural rule and weaker than two check digits.

#### Scenario: A real routing number is detected and near-misses are not
- **WHEN** the classifier scans text containing valid routing numbers and 9-digit look-alikes
- **THEN** the valid routing numbers are detected while a checksum-off-by-one and a valid-checksum-but-out-of-range-lead number read clean
