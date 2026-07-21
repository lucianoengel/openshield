# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier has a measured detection-quality floor
The classifier's detection quality MUST be measured against a labeled corpus that includes adversarial
near-misses, so its false-positive defense is a verified property rather than an untested assumption.

The checksum-backed detectors (CPF, credit card) MUST produce zero false positives on near-miss
numbers whose check digits are wrong, and MUST detect genuinely valid values (high recall). The SSN
detector, which has no checksum, MAY produce a materially higher false-positive rate on SSN-shaped
numbers — and the measurement MUST surface that ordering, making the low SSN confidence (D4/D5) a
measured fact. The measured numbers are recorded and act as a regression guard.

#### Scenario: Near-miss numbers do not false-positive on checksum detectors
- **WHEN** the classifier scans a corpus of clean text plus near-miss CPF/card numbers (a valid value
  with one digit flipped so its checksum fails)
- **THEN** the CPF and credit-card detectors flag none of the near-misses
- **AND** a test asserts a zero false-positive rate for those detectors on near-misses

#### Scenario: Valid PII is detected and the SSN weakness is surfaced
- **WHEN** the classifier scans a corpus of genuinely valid CPFs and Luhn-valid cards in realistic text,
  and of SSN-shaped numbers
- **THEN** recall on the valid CPF/card values meets a high floor, and the SSN false-positive rate is
  recorded and shown to exceed the checksum-backed detectors' false-positive rate
- **AND** a test records the precision/recall/false-positive numbers and asserts the SSN > CPF FP ordering
