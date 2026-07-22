# pattern-classifier (delta)

## ADDED Requirements

### Requirement: The classifier detects US EINs by format and IRS prefix
The classifier MUST detect a US Employer Identification Number by validating an NN-NNNNNNN
candidate against the IRS-assigned campus-prefix whitelist on its first two digits, and MUST NOT
report a number with an unassigned prefix nor a number in the SSN grouping. An EIN hit MUST carry a
moderate confidence reflecting structural-only evidence (no checksum), on par with SSN.

#### Scenario: A valid EIN is detected and an unassigned-prefix number is not
- **WHEN** the classifier scans text containing EINs with assigned and unassigned prefixes
- **THEN** the assigned-prefix EINs are detected while an unassigned-prefix number and an SSN-grouped number read clean
