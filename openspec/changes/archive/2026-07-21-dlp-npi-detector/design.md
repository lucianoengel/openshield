# Design — NPI detector

## Two guards, both load-bearing

A bare 10-digit run is common (it collides with phone numbers and ids), so two constraints make
it reportable: every NPI begins with 1 or 2, and every NPI carries a Luhn check digit computed
over the number prefixed with the fixed issuer id 80840. The prefix constraint eliminates ~80% of
the 10-digit space the checksum would otherwise let through; the checksum eliminates ~90% of the
rest. The test isolates each: a number that leads with 1 but fails Luhn (1234567894) exercises the
checksum, and a number that passes the 80840-prefixed Luhn but leads with 3 (3000000000, whose
prefixed Luhn sum is 30) exercises the leading-digit rule — so a mutation dropping either guard
fails a specific case.

## Confidence 0.80

A real check-digit scheme is strong, but a bare 10-digit run is common enough (unlike a 13–19
digit card) that the confidence sits just below the card Luhn. The phone detector requires
distinctive formatting, so a bare 10-digit run is not double-claimed as a phone.
