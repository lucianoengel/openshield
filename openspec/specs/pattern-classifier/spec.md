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
The classifier MUST have an automated test that measures detection quality on a labeled corpus and
asserts floors and ceilings tied to the validator strength — high recall on generated-valid PII,
zero false positives on checksum near-misses for the check-digit detectors, and the checksum-free
detector's false-positive rate materially exceeding a checksummed one. For detectors that match a
BARE digit run (no grouping) and rely on a checksum plus a leading constraint, the test MUST also
measure their false-positive rate on random numeric noise and bound it within the envelope implied
by that constraint, so a regression widening it is caught in aggregate.

#### Scenario: Detection quality holds and the bare-run FP rate stays bounded
- **WHEN** the detection-quality test runs over generated-valid PII, checksum near-misses, and random numeric noise
- **THEN** recall meets its floor, near-miss false positives are zero for the check-digit detectors, and the bare-run detectors' false-positive rate on random noise stays within its expected ceiling

### Requirement: The classifier detects secrets and credentials with structural validators
The classifier MUST detect private keys, cloud access keys, JWTs, and vendor API tokens using a
candidate pattern paired with a real validator (a PEM frame, a prefixed key id, a decodable JOSE
header, a distinctive vendor prefix), never a bare regex, so a look-alike string does not trip it.
The vendor-token detector MUST recognize the distinctive prefixes of the common secret formats —
including GitHub, Slack, Google, OpenAI/Anthropic, Stripe (live and restricted), GitLab, npm,
SendGrid, and Twilio — with a body length or charset floor that rejects truncated look-alikes, and
MUST report these at a high, calibrated confidence reflecting how distinctive the prefix is.

#### Scenario: A benign look-alike does not trip a secret detector
- **WHEN** the classifier scans a three-dotted non-JOSE token, an AKIA-shaped word, a public-key line, or a truncated or wrong-prefix vendor-token look-alike
- **THEN** none of the secret detectors fire

#### Scenario: A real vendor token is detected
- **WHEN** the classifier scans text containing a real vendor-prefixed token (GitHub, Slack, GitLab, npm, SendGrid, Stripe restricted, Twilio, …)
- **THEN** the API-token detector fires at its calibrated confidence

### Requirement: The classifier extracts text from Office documents before detection, bounded
The classifier MUST detect an Office Open XML container (DOCX/XLSX/PPTX) and extract the
text of its user-content members before running detectors, so content inside a document is
classified rather than its compressed bytes. Extraction MUST be bounded against a
decompression bomb — a per-member read limit, a total extraction ceiling, and an entry-count
cap — so a small archive declaring a huge expansion cannot exhaust memory. A non-document,
a corrupt archive, or an archive with no recognized text members MUST fall back to scanning
the raw bytes, never to scanning nothing.

#### Scenario: PII inside a document is detected and a bomb is bounded
- **WHEN** the classifier scans a DOCX/XLSX containing sensitive content
- **THEN** the content is extracted and detected; a non-document falls back to a raw scan; and a decompression bomb is bounded rather than exhausting memory

### Requirement: The classifier detects international financial and health PII with appropriate validators
The classifier MUST detect an IBAN via the ISO 7064 mod-97-10 checksum AND the correct
per-country length — a string that passes the checksum but is the wrong length for its
country, or carries an unknown country code, MUST be rejected — and MUST accept the
space-grouped printed form. It MUST detect health data via a keyword dictionary, requiring
multiple distinct terms and reporting low confidence, so a single common medical word does
not fire. A checksum-backed IBAN hit MUST carry high confidence; a dictionary-only health
hit MUST carry low confidence.

#### Scenario: A valid IBAN is detected and a wrong-length or weak look-alike is not
- **WHEN** the classifier scans an IBAN or health text
- **THEN** a mod-97-valid, correct-length IBAN is detected at high confidence, a wrong-length or unknown-country IBAN and a single-term health mention are not, and multi-term health text is detected at low confidence

### Requirement: The classifier extracts text from PDF documents, bounded and panic-contained
The classifier MUST detect a PDF (by its magic) and extract its text before running
detectors, so content inside a PDF is classified rather than its compressed byte structure.
Extraction MUST be bounded by the extraction ceiling and MUST contain a parser panic — a
malformed or hostile PDF MUST fall back to scanning the raw bytes, never crash the
classifier. The PDF parser MUST run in the sandboxed worker and MUST NOT be linked into the
privileged agent.

#### Scenario: Compressed PDF text is extracted and a malformed PDF does not crash
- **WHEN** the classifier scans a PDF whose text is compressed, and separately a malformed PDF
- **THEN** the compressed content is parsed and detected (not found in the raw bytes), and the malformed PDF falls back to a raw scan without crashing

### Requirement: The classifier loads operator-authored custom rules only when signed and verified
The classifier MUST accept custom detector rules only from a bundle whose Ed25519 signature
verifies against a trusted operator key; an unsigned, tampered, wrong-key, or malformed
bundle MUST load no rules and MUST return an error (fail-closed). A rule MUST be declarative
— a regex pattern plus a named built-in validator, never executable code — and a rule that
does not compile or is out of bounds MUST fail the entire bundle rather than load partially.
A custom rule MUST report the generic custom detector type, never a per-rule name, so it
cannot leak what it detects.

#### Scenario: A signed bundle loads and an untrusted one does not
- **WHEN** an operator-signed rule bundle is loaded with the trusted key
- **THEN** its custom rules fire (reported as the generic custom type) alongside the built-ins; and a wrong-key, tampered, or unsigned bundle loads nothing and errors

### Requirement: The worker loads operator-signed custom rules when configured, fail-closed
The worker MUST load operator-authored custom rules from a configured signed bundle, verified
against a configured trusted public key, and merge them with the built-in detectors. A missing
key, or an unreadable, unsigned, tampered, or wrong-key bundle MUST load no custom rules while
the worker continues to classify with the built-ins — an unverified rule MUST never be loaded,
and a bad optional bundle MUST NOT stop classification.

#### Scenario: A signed bundle applies and a tampered one does not
- **WHEN** the worker is configured with a rule bundle and trusted key
- **THEN** a valid signed bundle's custom detector fires, while a tampered or wrong-key bundle loads nothing and the built-ins still classify

### Requirement: The classifier detects distinctively-formatted phone numbers, low-FP
The classifier MUST detect a phone number by distinctive formatting — an E.164 country prefix,
a parenthesised area code, or separated groups — together with a plausible digit count, and MUST
NOT report a bare digit run, a timestamp, or a formatted string with an implausible digit count.
A phone hit MUST carry low confidence, reflecting the format-only (checksumless) evidence.

#### Scenario: A formatted phone is detected and a bare number is not
- **WHEN** the classifier scans text containing formatted phone numbers and bare digit runs
- **THEN** the formatted numbers are detected at low confidence while bare runs and implausible look-alikes read clean

### Requirement: The classifier detects US bank routing numbers by checksum and structure
The classifier MUST detect a US bank routing number (ABA) by validating a 9-digit candidate
against BOTH the ABA weighted mod-10 checksum AND the Federal Reserve routing-symbol leading-digit
range, and MUST NOT report a 9-digit run that fails either check. A routing-number hit MUST carry a
confidence between the checksumless structural detectors and the two-check-digit schemes, reflecting
that one checksum plus a range is stronger than a structural rule and weaker than two check digits.

#### Scenario: A real routing number is detected and near-misses are not
- **WHEN** the classifier scans text containing valid routing numbers and 9-digit look-alikes
- **THEN** the valid routing numbers are detected while a checksum-off-by-one and a valid-checksum-but-out-of-range-lead number read clean

### Requirement: The classifier detects Canadian SINs by grouping and Luhn checksum
The classifier MUST detect a Canadian Social Insurance Number by validating a conventionally
grouped candidate (NNN-NNN-NNN, hyphen or space separated) against the Luhn checksum, and MUST NOT
report a grouped number that fails Luhn nor a bare (ungrouped) 9-digit run. A SIN hit MUST carry a
confidence reflecting Luhn-over-a-distinctive-grouping — strong, and near the credit-card Luhn.

#### Scenario: A grouped Luhn-valid SIN is detected and look-alikes are not
- **WHEN** the classifier scans text containing grouped SINs and 9-digit look-alikes
- **THEN** the grouped Luhn-valid numbers are detected while a Luhn-off-by-one, a grouped-but-invalid number, and a bare ungrouped run read clean

### Requirement: The classifier detects US NPIs by leading digit and Luhn checksum
The classifier MUST detect a US National Provider Identifier by validating a 10-digit candidate
against BOTH the leading-digit rule (an NPI begins with 1 or 2) AND the Luhn checksum over the
80840-prefixed number, and MUST NOT report a 10-digit run that fails either check. An NPI hit MUST
carry a confidence reflecting a real check-digit scheme over a common-length run.

#### Scenario: A valid NPI is detected and near-misses are not
- **WHEN** the classifier scans text containing valid NPIs and 10-digit look-alikes
- **THEN** the valid NPIs are detected while a Luhn-off-by-one and a checksum-valid-but-wrong-leading-digit number read clean

### Requirement: The classifier detects UK NHS numbers by grouping and mod-11 checksum
The classifier MUST detect a UK NHS number by validating a 3-3-4 space-grouped candidate against
the NHS weighted mod-11 check digit, and MUST NOT report a grouped number with a wrong check digit
nor a bare (ungrouped) 10-digit run. An NHS hit MUST carry a confidence reflecting a real
check-digit scheme over a distinctive grouping.

#### Scenario: A valid grouped NHS number is detected and near-misses are not
- **WHEN** the classifier scans text containing grouped NHS numbers and 10-digit look-alikes
- **THEN** the valid grouped numbers are detected while a wrong-check-digit number and a bare ungrouped run read clean

### Requirement: The classifier detects US EINs by format and IRS prefix
The classifier MUST detect a US Employer Identification Number by validating an NN-NNNNNNN
candidate against the IRS-assigned campus-prefix whitelist on its first two digits, and MUST NOT
report a number with an unassigned prefix nor a number in the SSN grouping. An EIN hit MUST carry a
moderate confidence reflecting structural-only evidence (no checksum), on par with SSN.

#### Scenario: A valid EIN is detected and an unassigned-prefix number is not
- **WHEN** the classifier scans text containing EINs with assigned and unassigned prefixes
- **THEN** the assigned-prefix EINs are detected while an unassigned-prefix number and an SSN-grouped number read clean

### Requirement: Content inside archives is extracted and classified

The classifier SHALL extract and classify the content of files inside a ZIP archive, including a file
inside a nested archive (a zip within a zip), so a sensitive value placed in an archive is detected
rather than scanned as opaque compressed bytes. Extraction SHALL be bounded against a decompression
bomb by a total-size budget shared across the whole recursion and a maximum nesting depth; beyond the
bounds the remaining bytes are scanned as-is rather than expanded.

#### Scenario: A sensitive file in a plain zip is detected
- **WHEN** a sensitive value (e.g. a valid card number) is placed in a plain-text file inside a ZIP and classified
- **THEN** the corresponding detector reports a hit

#### Scenario: A double-zipped sensitive file is detected
- **WHEN** the sensitive file is inside a ZIP that is itself inside another ZIP
- **THEN** the detector still reports a hit

#### Scenario: A non-archive is scanned as-is
- **WHEN** the input is plain text (not an archive)
- **THEN** it is scanned directly and detection is unchanged

#### Scenario: A decompression bomb is bounded
- **WHEN** a deeply nested or oversized archive is classified
- **THEN** extraction stops at the size/depth bounds without exhausting memory
