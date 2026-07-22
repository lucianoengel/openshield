## Context

Phone numbers have no checksum and a bare 10-digit run collides with too much to be worth its
false positives — so, like SSN and email, this is a format+low-confidence detector.

## Goals / Non-Goals

**Goals:** detect distinctively-formatted phone numbers, low-FP, low confidence.

**Non-Goals:** national number-plan validation; vanity numbers; word-spelled numbers.

## Decisions

**Format AND a plausible digit count.** A phone is recognized by distinctive formatting
(separators, an E.164 +country prefix, or parentheses) — a bare digit run is NOT a phone — and
the matched string must carry 7–15 digits (E.164's max is 15). Both are required, so an
order-id-shaped run and a +formatted string with too few digits both read clean. The confidence
is low (0.55), reflecting format-only evidence, exactly as SSN/email are capped.

## Risks / Trade-offs

- **A checksumless detector is inherently approximate.** The format+digit-count keeps FP low but
  a formatted non-phone (a formatted product code) could match; the low confidence signals this,
  and a policy weights it accordingly.
