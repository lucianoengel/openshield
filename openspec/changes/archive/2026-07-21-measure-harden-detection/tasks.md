# Tasks — measure & harden detection

## 1. Classifier corpus + measurement (Part A)

- [x] 1.1 Corpus helpers: generate valid CPFs and Luhn-valid cards (compute check digits), near-misses (flip one digit so the checksum fails), and SSN-shaped numbers; commit realistic clean text fixtures (prose/code/logs) under `internal/classify/testdata/`.
- [x] 1.2 Measurement harness: scan each labeled item, tally a per-detector confusion matrix, compute precision/recall/FP, and log the numbers.
- [x] 1.3 **Test**: CPF and card FP rate on near-misses == 0; recall on valid CPF/card ≥ a high floor.
- [x] 1.4 **Test**: SSN FP rate on SSN-shaped numbers is recorded and asserted to exceed the checksum detectors' FP (the measured reason SSN confidence is capped, D4/D5).

## 2. peer-UEBA leave-one-out (Part B.1)

- [x] 2.1 `ContextFor` computes mean/std over the OTHER subjects (exclude the subject under test); require ≥ 2 other subjects for peers, else nil Context.
- [x] 2.2 **Test**: a strong outlier scores strictly higher with leave-one-out than with self-included; small population still returns nil.

## 3. peer-UEBA time decay (Part B.2)

- [x] 3.1 Add a deterministic decay: an injected time source (default real monotonic clock), counts decay by a half-life on update/read. `Observe` records the time; `ContextFor` decays to the read time.
- [x] 3.2 **Test**: a steady-but-busy subject stays bounded near its peers (not flagged) under decay, and WOULD drift into outlier under the old cumulative count; a genuine burst still spikes.
- [x] 3.3 **Test**: the public API (Observe/ContextFor/Resolver) and context_version (D53) are unchanged — existing peer-UEBA + fleet tests still pass.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` new D-number: the classifier now has a measured FP/recall floor (checksum near-miss FP == 0; SSN weakness measured); peer-UEBA hardened with leave-one-out + decay; synthetic corpus validates the checksum defense, NOT field base rates (still needs T-015).
- [x] 4.2 `openspec validate measure-harden-detection --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| CPF checksum accepts any value | `TestClassifierDetectionQuality` (near-miss FP jumps) |
| baseline includes the subject (not leave-one-out) | `TestLeaveOneOutBeatsSelfIncluded` |
| no decay (count returned unchanged) | `TestDecayRetiresAStaleBurst` |
| drop the std floor | `TestPeerAlertOnVerifiedOutlier` (decay-noise false alert returns) |

MEASURED (synthetic corpus, N=200): CPF recall 1.000 / near-miss+clean FP 0.000;
card recall 1.000 / near-miss+clean FP 0.000; SSN (no checksum) FP on SSN-shaped
1.000 — the measured reason SSN confidence is capped (D4/D5). peer-UEBA: an
outlier scores strictly higher under leave-one-out than self-included; a stale
burst decays out of anomaly (0.000) where a cumulative count keeps it flagged
(1.000). Hardening surfaced a real flaw — decay noise + near-uniform peers made
z-scores explode — fixed with a coefficient-of-variation std floor. Public API
and context_version unchanged; existing peer-UEBA + fleet tests pass. Synthetic
corpus validates the checksum FP defense and discrimination, NOT field base rates
(still needs dogfood, T-015).
