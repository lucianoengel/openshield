## Context

IBAN and health data extend the existing detector shape. IBAN has a real checksum (mod-97),
so it joins the strong detectors; health data has none, so it joins the weak, capped ones.

## Goals / Non-Goals

**Goals:** strong IBAN detection (mod-97 + length); conservative, low-FP health-data
evidence.

**Non-Goals:** passport numbers; exhaustive IBAN coverage; dictionary localization.

## Decisions

**IBAN: mod-97 AND a per-country fixed length.** The mod-97-10 check (ISO 7064) is the
primary validator; the per-country length is a second, load-bearing guard — a string can
pass mod-97 yet be the wrong length for its country (the test includes exactly such a
string, and asserts it is rejected). An unknown country code is rejected outright. The
printed space-grouped form is normalized (spaces stripped) before validation.

**Health data: multiple terms, low confidence — the honest treatment of a validator-free
detector.** No checksum exists, so a single medical word ("diagnosis") is too common to
report; the detector requires ≥3 distinct terms and reports low confidence. It is
corroborating evidence for a policy, never a strong standalone hit — the same discipline
that caps SSN and email.

## Risks / Trade-offs

- **Dictionary detectors are inherently approximate.** The threshold and term list trade
  recall for precision; tuning against real corpora (T-015) is the eventual calibration. An
  admin-authorable dictionary (D3) is the general answer.
- **IBAN country coverage is a subset.** Representative (SEPA/EU + a few); an unknown code
  is rejected rather than guessed, so the failure mode is a miss, not a false positive.
