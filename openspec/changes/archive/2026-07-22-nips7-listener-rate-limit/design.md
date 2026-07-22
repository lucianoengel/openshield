# Design — listener admission rate limit

## Global bucket, because sources are spoofable

A per-source rate limit is the intuitive choice, but a UDP source IP is trivially spoofed, so an
attacker rotates spoofed sources and each gets its own budget — no bound at all. A GLOBAL token
bucket on the listener bounds the TOTAL admission rate regardless of claimed source, which is what
actually caps the ledger-write rate. The bucket admits a burst (normal traffic spikes) then a
sustained rate; beyond it, datagrams are dropped before they become events.

## Drop before the ledger write

The limit is checked at the top of the receive loop, before parse+sink — so a rate-dropped datagram
never mints a pipeline event and never reaches the ledger. It is counted in a dedicated counter so a
flood is observable (a spike in RateLimited is the signal), distinct from a parse drop.

## Deterministic test

The limiter takes an injectable clock. The listener test sets a burst-of-1, zero-refill, frozen-clock
limiter and floods 20 datagrams: exactly one (the burst) reaches the sink and the rest are
rate-limited. Removing the check lets all 20 through — the mutation fails. The limiter's own test
drives the clock forward to prove the sustained refill.
