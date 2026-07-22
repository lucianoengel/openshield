# DLP: bound the false-positive rate of the bare-run detectors

## Why

The ABA (9-digit) and NPI (10-digit) detectors match a BARE digit run and rely on a checksum plus a
leading constraint. Unlike the grouped detectors (SIN/NHS/EIN, which need a specific separator
layout that rarely occurs by chance), a bare-run detector fires on a predictable fraction of RANDOM
numeric noise — roughly the checksum-pass rate times the leading-digit fraction. This is an honest,
inherent tradeoff (and the reason their confidence is capped below 1.0), but it was unmeasured, so a
regression that widened it — e.g. dropping the leading constraint, taking the rate from ~4% to ~10%
— would pass the isolated unit tests unnoticed in aggregate.

## What Changes

- **A precision guard** measures the ABA and NPI false-positive rate over 20,000 random 9/10-digit
  runs and asserts it stays within its expected envelope (ABA ≤ 7%, NPI ≤ 4%; measured ~4% / ~2%).
  A regression that weakens a constraint (rate ~10%+) trips the ceiling in aggregate, complementing
  the isolated unit mutation tests.

This adds a test to the `pattern-classifier` capability's detection-quality floor. No production
code change.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `internal/classify/noise_precision_test.go` (new test only).
- Not in scope (stated): changing the detectors' confidence or requiring context keywords to lower
  the bare-run FP further (a policy/tuning decision — the measured envelope is documented so the
  tradeoff is explicit); a precision guard for the grouped detectors (they do not match bare runs).
