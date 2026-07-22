# Design — modern token prefixes

## Prefix is the validator, length is the filter

Like the existing token alternatives, each new one is a published, distinctive vendor prefix
followed by a body length (and, for Twilio, charset) floor. The prefix carries essentially all
the evidence — `glpat-`, `npm_`, `SG.`, `rk_live_`, `SK`+hex do not occur by accident — and the
length floor rejects a truncated fragment. No decode or checksum is possible (these are opaque
secrets), so the confidence stays where the other prefixed tokens sit (0.90).

## Choosing live/restricted over test

Stripe and GitLab issue both live and test/less-privileged variants. The detector targets the
sensitive ones (`rk_live_`, live keys) rather than test keys, whose leak is low-impact — a
deliberate precision choice that keeps the detector's hits actionable.

## Mutation proof

Each alternative is independently load-bearing: removing the `glpat-` or the `SK`+hex alternative
makes exactly its positive case read clean, so the per-prefix tests fail. The look-alike negatives
(underscore instead of dash, too-short npm body, missing SendGrid segment, test-mode key, non-hex
Twilio body) prove the floors are enforced.
