## 1. Detector engine

- [x] 1.1 `internal/classify` package: `Detector` interface (`Type`, `Scan(text) (count, confidence)`)
      and a `Classifier` that runs a fixed registry and returns `[]*corev1.DetectorHit`
- [x] 1.2 All patterns compiled with `regexp` (RE2). No third-party backtracking engine added —
      verify by grepping the package's dependency graph in the test for a backtracking matcher
- [x] 1.3 Read the bounded stream with `io.ReadAll`; a read error returns an error, never empty hits

## 2. Detectors with validators

- [x] 2.1 CPF: candidate regex, strip formatting, verify both check digits mod 11, reject
      all-same-digit sequences. Confidence 0.95
- [x] 2.2 Credit card: candidate regex, strip separators, Luhn, length 13–19. Confidence 0.90
- [x] 2.3 SSN: hyphenated candidate, SSA structural rules (area ≠ 000/666/900–999, group ≠ 00,
      serial ≠ 0000). Confidence 0.60, with a comment stating SSN has no checksum
- [x] 2.4 Email: format only. Confidence 0.50
- [x] 2.5 Count is distinct valid matches; de-dup by normalized value in a set held only during
      the scan and never emitted

## 3. Tests — detection

- [x] 3.1 **Test**: seeded CPF, card, SSN each detected with the right type and count.
      `TestDetectsSeededPII`
- [x] 3.2 **Test**: wrong-check-digit CPF and Luhn-failing 16-digit number produce NO hit —
      proves the validator runs. `TestFormatWithoutChecksumIsRejected`
- [x] 3.3 **Test**: known Luhn/CPF vectors validate; known invalids reject.
      `TestChecksumVectors` (table of published valid/invalid numbers)
- [x] 3.4 **Test**: SSN confidence < CPF confidence, encoding the honest weakness.
      `TestSSNIsAWeakerSignalThanCPF`

## 4. Tests — the privacy invariant

- [x] 4.1 **Test**: classify a document of seeded values, serialize the hits, grep the wire
      bytes for every seeded substring — none may appear. `TestNoSeedValueOnTheWire`
- [x] 4.2 **Test**: two documents with different values but equal counts produce identical hits —
      the count/confidence carry no per-value signal. `TestCountIsNotADigest`
- [x] 4.3 **Mutation note**: add matched text to a hit → 4.1 must fail. Record the result.

## 5. Tests — the fail-open / ReDoS property

- [x] 5.1 **Test**: an adversarial backtracking-stress input classifies in linear time (a
      generous wall-clock ceiling that RE2 meets and a backtracking engine would blow).
      `TestNoCatastrophicBacktracking`

## 6. Wire into the worker

- [x] 6.1 Construct the real `Classifier` in `cmd/openshield-worker`; the fake stays test-only
- [x] 6.2 **Test**: the process-boundary test (T-006) now classifies a seeded CPF file end to
      end through the real classifier and gets a CPF hit with count ≥ 1
- [x] 6.3 Confirm `scripts/check-agent-deps.sh` still passes — the classifier is in the worker,
      whose dependency graph MAY hold parsers; the privileged binary's may not

## 7. Docs

- [x] 7.1 Record the RE2/linear-time decision in `docs/decisions.md` (new D-number): a
      backtracking engine on attacker-influenced bytes is a fail-open primitive
- [x] 7.2 Mark T-007 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| CPF validator always returns true (checksum skipped) | `TestFormatWithoutChecksumIsRejected`, `TestChecksumVectors` |
| count made value-derived (sum of matched digits) | `TestCountIsNotADigest` — hits differed between documents with equal counts |
| (structural) a content field added to a hit | `TestNoSeedValueOnTheWire` — the wire-byte grep is the standing guard; `DetectorHit` has no content field to add today, and this test fails the moment one is |

`TestNoCatastrophicBacktracking` stands guard on the RE2 requirement: a switch to
a backtracking engine would make it hang or blow its 5s deadline. Detection runs
end to end through the real classifier across the process boundary
(`TestPrivilegedTalksToWorkerAcrossProcessBoundary` now asserts a CPF hit from a
seeded file), and `scripts/check-agent-deps.sh` confirms the privileged binary
still holds no parser — the classifier is in the worker, where parsing belongs.
