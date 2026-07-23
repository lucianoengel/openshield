## Context

`contextNear` (D199) gates a weak-format value on a nearby keyword; the checksum detectors (CA-SIN, NPI,
UK-NHS via Luhn/mod-11) validate a strong-format value with a check digit. This ticket adds two national
IDs, one of each kind: Aadhaar (checksum) and NINO (context).

## Goals / Non-Goals

**Goals:**
- Detect India Aadhaar via its real Verhoeff checksum (low FP, no context needed).
- Detect UK NINO via `contextNear` + the official format/prefix rules.
- Reuse the existing mechanisms exactly — no new detection framework.

**Non-Goals:**
- Every country's national ID — two high-value ones this increment; the primitive/checksum shapes make
  more a copy-paste follow-on.
- A configurable per-country toggle — the built-ins always run (a policy weighs the hit).

## Decisions

1. **Aadhaar = Verhoeff checksum + first-digit 2–9.** Aadhaar is 12 digits whose last digit is a Verhoeff
   check over the preceding ones, and the first digit is never 0 or 1. The Verhoeff algorithm (d/p/inv
   tables) is the published validation — a real check-digit scheme, so like CA-SIN it needs no context
   keyword. The candidate regex matches the conventional 4-4-4 spaced or bare 12-digit form; a bare
   12-digit run that fails Verhoeff is not counted, which filters the vast majority of coincidences.

2. **NINO = format + prefix rules + contextNear.** NINO is two prefix letters (with exclusions: D, F, I,
   Q, U, V not as either letter; O not second; the first two are not certain admin prefixes), six
   digits, one suffix A–D. It has NO checksum, so — exactly like passport/DL — it is context-gated:
   counted only near a "national insurance"/"NI number"/"NINO" keyword. This reuses `contextNear`, the
   DLP-7 primitive the roadmap points at.

3. **Confidence.** Aadhaar reports the checksum-tier confidence (strong, like CA-SIN); NINO reports the
   context-tier `confContext` (moderate — the keyword filters FPs but there is no checksum).

## Risks / Trade-offs

- **Verhoeff correctness.** The tables are transcribed from the published algorithm and covered by tests
  with known-valid and known-invalid Aadhaar-shaped numbers, including a single-digit-tamper case (the
  property a checksum exists to catch).
- **NINO without context is not fired.** A NINO with no nearby keyword is missed — the deliberate DLP-7
  trade (precision over recall for checksumless IDs); a policy that needs bare-format recall can add a
  signed custom rule.
- **Bare 12-digit Aadhaar candidates** (phone-adjacent numbers) mostly fail Verhoeff (~90% rejected);
  the checksum is the precision, consistent with how bare-9-digit SSN/SIN are handled.
