# Design — SIEM-1 event search

## Mirror the peer-alert search, don't reinvent it

`SearchPeerAlerts` (SEC-8) already established the safe shape for an operator search over an
aggregate: parameterized WHERE built only from set constraints, a hard limit cap enforced both
at the parse layer and inside the query function (defense in depth for a direct caller), and a
parse step that errors on any malformed value rather than silently dropping it. `SearchTelemetry`
follows that shape exactly. Reusing `maxSearchLimit` and the fail-loud parse idiom keeps one
security contract across both search surfaces rather than two subtly different ones.

## Metadata, not payloads

The obvious temptation is to return the whole row including `payload`. Two reasons not to:
a search LIST that base64-dumps every raw proto is heavy and effectively unbounded per row, and
it changes the risk profile of the endpoint (bulk-exporting the aggregate rather than locating
within it). The search answers "which events match" — the operator then fetches one by id via
the existing `TelemetryForEvent` to see its payload. So `EventRow` is metadata only. `verified`
is included because whether a row is attributable is exactly what an investigator triages on.

## VerifiedOnly is the security-relevant guard

`verified` distinguishes telemetry checked against an enrolled agent key (D44) from legacy
self-asserted rows. Presenting the two together as if equivalent would let an investigator treat
self-asserted data as evidence. `VerifiedOnly` is therefore the guard most worth proving by
mutation: disabling the `verified = true` clause must make a verified-only search leak the
self-asserted row, and the test contains exactly that row so the clause is exercised.

## The cap is proven at the parse layer

Proving the in-query clamp directly would require seeding >1000 rows. Instead the cap is proven
where it is cheap and equivalent: `parseEventFilter` clamps a 1,000,000-row ask to
`maxSearchLimit`, honors a below-cap ask exactly, and errors on a non-numeric limit. Removing the
clamp fails the test. The in-query clamp is defense-in-depth for direct (non-HTTP) callers,
mirroring `SearchPeerAlerts`.
