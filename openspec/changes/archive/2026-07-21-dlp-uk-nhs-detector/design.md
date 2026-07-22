# Design — UK NHS detector

## Space-grouped 3-3-4 plus mod-11

An NHS number is ten digits with a weighted mod-11 check digit (weights 10..2 over the first
nine). A bare ten-digit run collides with too much (and with the NPI detector's space), so the
detector requires the canonical 3-3-4 SPACE grouping. Space rather than hyphen is deliberate: the
hyphen/dot 3-3-4 form is the phone shape, and requiring spaces keeps NHS and phone from
double-claiming the same string. The mod-11 check is the strong evidence; the grouping makes it a
candidate.

## The check==10 rule

The NHS algorithm maps a computed check of 11 to 0 and treats a computed check of 10 as marking an
INVALID number (no valid NHS number has that check digit). Both are handled, so a number whose
weighting produces check 10 is rejected rather than mis-accepted.

## Mutation proof

The mod-11 comparison is the load-bearing guard: two grouped numbers with a wrong check digit
(943 476 5910 / 5911) must read clean, so disabling the comparison trips both. The grouping
discipline is proven by a bare, ungrouped valid-digit number reading clean.
