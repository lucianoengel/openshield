# pattern-classifier delta

## ADDED Requirements

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
