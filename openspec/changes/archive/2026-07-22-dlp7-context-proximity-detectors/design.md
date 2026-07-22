## Context

Each detector implements `Scan(text) → (count, confidence)`. The checksum/structural detectors validate
the value itself; weak-format identifiers have no such validator, so their precision must come from
context — a nearby keyword. `contextNear` is the shared primitive; passport and driver's license are its
first uses.

## Goals / Non-Goals

**Goals**
- `contextNear(valueRe, keywordRe, window, text)` — distinct values with a keyword within the window.
- `passport` and `driversLicense` detectors; distinct detector types; added to the default set.
- Prove the context precision (value+keyword fires; value alone does not).

**Non-Goals**
- Linguistic/label parsing (a byte-window heuristic here).
- Non-US formats (follow-ons reusing the primitive; operators can also author custom context rules).
- A checksum for these (they have none — context is the precision).

## Decisions

### D1 — Context proximity is a byte window, not parsing
For each value match, `contextNear` checks whether a keyword regex matches within `window` bytes before
or after the value in the extracted text. This is a simple, robust heuristic: it catches "Passport:
123456789" and "123456789 (passport)" without a parser, and its false-positive control is that a bare
number far from any keyword never fires. Richer context (sentence/label structure) is a refinement; the
byte window is the low-FP, no-dependency choice consistent with the other detectors.

### D2 — Weak-format identifiers are context-REQUIRED
A passport is a 9-digit (or letter+8-digit) run and a driver's license is a state-variable alphanumeric —
both far too generic to fire on format alone (every order number would match). So these detectors require
the keyword: no keyword nearby → no hit. This is the opposite of a checksum detector (which fires on the
value alone) and is the honest way to detect them — the value pattern is necessary but not sufficient.

### D3 — Distinct detector types, de-duplicated counts
Passport and driver's license get their own `DETECTOR_TYPE_*` so a policy routes them (a passport leak is
its own signal), keeping the closed enum meaningful. Counts de-dup on the normalized value (as the other
detectors do) so a repeated fixture does not inflate the count, and no matched text crosses the boundary
(D10) — only type + confidence + count.

### D4 — Confidence reflects context-gated-but-checksumless
A context-gated structural match is stronger than a bare structural one (the keyword filters most FPs)
but weaker than a checksum. So confidence sits in the moderate band (like SSN/EIN), not near 1.0 — an
honest signal a policy weighs, never treated as certainty (D4).

## Risks / Trade-offs

- **Window size** — too small misses a legitimate label a few words away; too large re-admits FPs. A
  ~40-byte window balances the two; it is a constant that can be tuned.
- **Broad DL value pattern** — the alphanumeric pattern is generous, but the required keyword is the
  precision; without the keyword it never fires, so the breadth costs nothing.

## Migration Plan

Additive: two proto enum values (regenerated), a helper + two detectors added to `New()`. The existing
detectors and the classification contract shape are unchanged.

## Open Questions

- Whether to expose the window/keyword set as operator-tunable config (vs constants). Constants here;
  operator context rules already exist via the signed custom-rule surface.
