# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier detects distinctively-formatted phone numbers, low-FP
The classifier MUST detect a phone number by distinctive formatting — an E.164 country prefix,
a parenthesised area code, or separated groups — together with a plausible digit count, and MUST
NOT report a bare digit run, a timestamp, or a formatted string with an implausible digit count.
A phone hit MUST carry low confidence, reflecting the format-only (checksumless) evidence.

#### Scenario: A formatted phone is detected and a bare number is not
- **WHEN** the classifier scans text containing formatted phone numbers and bare digit runs
- **THEN** the formatted numbers are detected at low confidence while bare runs and implausible look-alikes read clean
