# Design — ABA routing detector

## Two validators, both load-bearing

A bare 9-digit run is far too common to report on format alone (it collides with order ids,
timestamps, unhyphenated SSNs). Two independent constraints make it reportable:

- The ABA weighted mod-10 checksum — the strong evidence, like Luhn for cards. But a checksum
  alone still passes roughly 1 in 10 arbitrary 9-digit runs.
- The Federal Reserve routing-symbol range on the first two digits (00–12, 21–32, 61–72, 80) —
  cheap structural evidence that eliminates most of the numeric space the checksum would let slip.

Requiring BOTH is what separates this from a false-positive machine. The test isolates each: a
number with a valid lead but a broken checksum (`123456789`) exercises the checksum, and a number
with a valid checksum but an out-of-range lead (`990000000`, whose weighted sum is 90) exercises
the range — so a mutation dropping either guard fails a specific case.

## Confidence placement

0.75 sits deliberately between the checksumless structural detectors (SSN 0.60, phone 0.55) and
the two-check-digit schemes (CPF 0.95, card 0.90). One checksum plus a range is stronger than a
structural rule and weaker than two independent check digits — the confidence says so, honestly,
and a policy reading it as certainty is the mistake calibrated confidence exists to prevent.

## An additive enum value

`DETECTOR_TYPE_ABA_ROUTING = 13` extends the closed enum without renumbering — backward
compatible, the way the enum already grew (phone, iban, custom were each added the same way).
The detector emits this type with type + confidence + count only; no content crosses the worker
boundary, exactly like the others.
