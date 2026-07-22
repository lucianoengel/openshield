# pattern-classifier (delta)

## ADDED Requirements

### Requirement: The classifier detects US NPIs by leading digit and Luhn checksum
The classifier MUST detect a US National Provider Identifier by validating a 10-digit candidate
against BOTH the leading-digit rule (an NPI begins with 1 or 2) AND the Luhn checksum over the
80840-prefixed number, and MUST NOT report a 10-digit run that fails either check. An NPI hit MUST
carry a confidence reflecting a real check-digit scheme over a common-length run.

#### Scenario: A valid NPI is detected and near-misses are not
- **WHEN** the classifier scans text containing valid NPIs and 10-digit look-alikes
- **THEN** the valid NPIs are detected while a Luhn-off-by-one and a checksum-valid-but-wrong-leading-digit number read clean
