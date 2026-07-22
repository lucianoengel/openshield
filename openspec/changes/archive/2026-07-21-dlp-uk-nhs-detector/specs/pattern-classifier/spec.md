# pattern-classifier (delta)

## ADDED Requirements

### Requirement: The classifier detects UK NHS numbers by grouping and mod-11 checksum
The classifier MUST detect a UK NHS number by validating a 3-3-4 space-grouped candidate against
the NHS weighted mod-11 check digit, and MUST NOT report a grouped number with a wrong check digit
nor a bare (ungrouped) 10-digit run. An NHS hit MUST carry a confidence reflecting a real
check-digit scheme over a distinctive grouping.

#### Scenario: A valid grouped NHS number is detected and near-misses are not
- **WHEN** the classifier scans text containing grouped NHS numbers and 10-digit look-alikes
- **THEN** the valid grouped numbers are detected while a wrong-check-digit number and a bare ungrouped run read clean
