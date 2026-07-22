# pattern-classifier (delta)

## MODIFIED Requirements

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
