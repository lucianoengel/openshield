# Design — CONSOLE-6

## Keyset, not OFFSET, and the reason is the live stream

`OFFSET 1000` re-runs the query and discards rows. Against `fleet_telemetry`, which is being written
continuously, rows arriving at the head shift every later row down — so page 2 repeats what page 1 showed
and skips what it did not. An analyst hunting through a fleet's telemetry would be reading a result set
that quietly lies about what it contains.

Keyset pagination walks from a fixed point: `(received_at, id) < (last_seen_pair)`. New rows land above
the walk and are simply not in it. That is a *stated* limit rather than a silent corruption.

## The cursor is opaque but NOT secret, and carries no authority

Opaque so clients do not build on its internals and so the encoding can change. **Not secret**, because
treating it as a secret invites treating it as a capability — and the moment a cursor is a capability,
replaying someone else's is privilege escalation.

So: the cursor encodes a POSITION only. Authority is re-derived from the principal on the request context
on every page (D470). A cursor lifted from another operator's session gets that operator's *position* and
the lifter's *authority*, which is exactly the intended outcome.

The guard is a test that pages with a cursor minted under one credential using a different credential, and
asserts the second caller's authority governs.

## A malformed cursor is refused, never ignored

Silently starting from the beginning would hand back page 1 while the client believes it is on page 5 —
the client then renders a duplicate page and, worse, concludes the data changed under it. `400` with the
reason, consistent with SEC-8 everywhere else on this surface.

## `has_more` is derived by over-reading one row

Ask for `limit + 1`, return `limit`, and report `has_more` from whether the extra row existed. A separate
`COUNT(*)` over a 90-day partition is expensive and — under live ingest — answers a different question
than "is there another page".

The over-read row is discarded, never returned, so `limit` means what it says.

## `next_cursor` is absent on the last page, not empty

Same rule as risk on the entity surface and last-seen on the fleet roster: a value a client could mistake
for a usable one must be absent. An empty-string cursor invites a client to send it back.
