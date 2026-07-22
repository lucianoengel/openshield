# Design — Canadian SIN detector

## Grouping plus Luhn, like the other checksum PII

A SIN is nine digits with a Luhn check. Nine bare digits collide with order ids, SSNs, and ABA
routing numbers, so — as with SSN — the detector requires the conventional grouped format
`NNN-NNN-NNN` (hyphen or space) rather than any 9-digit run. The grouping makes it a SIN
candidate; the Luhn checksum is the strong evidence that filters look-alikes. Requiring the
grouping is the deliberate FP trade: a genuinely bare SIN is missed, but the far more numerous
bare 9-digit non-SINs do not fire.

## Confidence 0.85

Luhn over a distinctive grouping is strong evidence, placed just below the credit-card Luhn
(0.90): a 9-digit number has a slightly higher chance of passing Luhn by luck than a 13–19 digit
card, so the confidence is a notch lower — honest calibration, not a round number.

## Mutation proof

The Luhn validator is the load-bearing guard: a well-grouped but Luhn-invalid number
(`123-456-789`) and a valid SIN with its last digit changed (`046-454-287`) must read clean, so
disabling the Luhn check trips both. The grouping discipline is proven by a bare, ungrouped but
otherwise-valid number reading clean.
