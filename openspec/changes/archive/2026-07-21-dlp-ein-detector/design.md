# Design — EIN detector

## Format plus prefix whitelist, no checksum

An EIN carries no check digit, so — like SSN — it relies on structure. Two things make it
reportable: the distinctive `NN-NNNNNNN` grouping (a 2-7 hyphenation, unlike the SSN 3-2-4 shape,
so the two do not collide), and the IRS campus-prefix whitelist on the first two digits. The
prefix set is published (the assigned campus codes); a number whose prefix is not on it was never
a validly-issued EIN. This is a whitelist rather than a checksum, so the confidence is moderate
(0.60), matching SSN's structural-only evidence — honest calibration, not a hopeful high number.

## Mutation proof

The prefix whitelist is the load-bearing validator: two well-formed numbers with unassigned
prefixes (07-, 00-) must read clean, so bypassing the whitelist trips both. The format discipline
is proven by an SSN-grouped number reading clean (wrong shape for the EIN candidate).
