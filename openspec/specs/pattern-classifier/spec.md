# pattern-classifier Specification

## Purpose
The endpoint pattern classifier: format-plus-checksum detection for named PII types, running in the unprivileged worker on a linear-time matcher, emitting type + confidence + count only — never content, never a reversible digest, never certainty.
## Requirements
### Requirement: Detection is format plus checksum, and reports calibrated confidence
The classifier MUST detect CPF, credit card and SSN by matching a candidate format and then
applying a validator, and MUST report a confidence that reflects the strength of that validator.
Confidence MUST never be reported as 1.0.

A format match alone is a weak signal — any 11 digits look like a CPF. The check digit is what
makes it evidence. Reporting certainty for a probabilistic match is the failure D4 forbids: a
policy author who sees 1.0 treats classification as truth, and classification is never truth.

#### Scenario: Checksum-valid PII is detected
- **WHEN** a document contains a CPF with valid check digits, a Luhn-valid card, and a
  structurally valid SSN
- **THEN** each is detected and reported with its detector type and a count
- **AND** a test asserts detection against seeded fixtures of each type

#### Scenario: Checksum-invalid candidates are rejected
- **WHEN** a document contains an 11-digit number with wrong CPF check digits and a 16-digit
  number that fails Luhn
- **THEN** neither is reported
- **AND** a test asserts that format-without-checksum does not produce a hit, so the validator
  is proven to run rather than assumed

#### Scenario: SSN's missing checksum is reflected, not hidden
- **WHEN** a structurally valid SSN is detected
- **THEN** its confidence is lower than a checksum-backed detector's
- **AND** the code documents that SSN has no checksum, so the weaker signal is a known property
  rather than a bug

### Requirement: The classifier emits no content and no reversible digest
Detector output MUST carry only detector type, confidence and count. It MUST NOT carry matched
text, offsets, hashes, fingerprints or embeddings. Matched content exists only inside the
worker and never crosses into the emitted hits.

For low-entropy PII a hash IS the value: CPF, SSN and cards are brute-forceable (D10), and a
similarity-preserving fingerprint reconstructs the input (D11). The count reveals how many
matched, not what they were.

#### Scenario: Serialized output contains none of the seeded values
- **WHEN** a document of seeded CPF, card and SSN values is classified and the resulting hits
  are serialized to their wire form
- **THEN** no substring of any seeded value appears in the serialized bytes
- **AND** this is asserted by a test that greps the wire bytes, because a negative property
  stated in prose rots — a future field addition must fail this test, not a review

#### Scenario: The count is not a digest
- **WHEN** two documents contain different PII values but the same number of each type
- **THEN** their emitted hits are identical
- **AND** a test asserts this, so a regression that smuggled a per-value signal into the count
  or confidence is caught

### Requirement: An error is never a clean result
If the classifier cannot complete — a read error, a malformed stream — it MUST return an error,
not an empty hit list. Empty hits mean "scanned, found nothing"; an error means "did not scan".

Conflating them is the quietest failure in a detection product: a crashing parser would make
every file it chokes on look clean, which is exactly the evasion a hostile file would aim for.

#### Scenario: A read failure surfaces as an error
- **WHEN** the input reader returns an error partway through
- **THEN** Classify returns an error and no hits
- **AND** the worker turns that into a response error, not a clean result

### Requirement: The matcher is linear-time
The detector engine MUST use a linear-time matcher (RE2-class). A backtracking regex engine MUST
NOT be introduced for detection.

Classification runs on attacker-influenced bytes. A pattern that can be driven to
catastrophic backtracking is a denial-of-service and, because slow classification fails open
(D17), a Block-to-Allow bypass. Linear-time matching removes the primitive entirely.

#### Scenario: A pathological input does not blow up matching
- **WHEN** an adversarial input designed to stress backtracking (long runs of partial matches)
  is classified
- **THEN** matching completes in time linear in the input length
- **AND** a test exercises such an input, so a future switch to a backtracking engine would be
  caught by the test timing out or failing rather than by a production incident

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

