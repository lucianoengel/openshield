# Every discard counter is incremented and eight of them are unobservable

## Why

`internal/controlplane` declares 20 `atomic.Int64` counters. **Eight are never rendered on
`/metrics`**, and they are precisely the ones covering the SIEM's front door:

- `CEFIngested` / `CEFDropped` — external syslog logs persisted vs. skipped
- `CloudTrailIngested` / `CloudTrailDropped`
- `WEFIngested` / `WEFDropped`
- `EntityResolveFailures` — device/user rows that never landed in the entity graph
- `RetentionRecordFailures`

Each was written with a comment explaining that it exists so a discard is not silent. `CEFDropped`'s
says the drop is "COUNTED … never silent". `EntityResolveFailures` says a non-zero value means some
device "did not land in the graph, observable rather than silent". None of them are observable by
anything.

**And a comment states the opposite of the truth.** Beside the CEF counters:

> The names are kept because they are exposed on `/metrics` and renaming them would break every
> dashboard built on them

They are not exposed. No dashboard can be built on them. A future maintainer reading that comment
would decline a rename to protect users who cannot exist.

The listener objects are the same story: `RateLimited()`, `Oversize()` and `Refused()` — admission
refusals, over-bound messages, and connections turned away at the concurrency cap — have **zero**
readers anywhere in the tree. `Dropped()` has exactly one.

So a deployment cannot distinguish "the estate is quiet" from "we refused most of it at the door",
which is the D31 gap this platform forbids everywhere else, sitting on the ingest path that carries
somebody else's evidence.

## What Changes

- The eight unexposed counters are rendered on `/metrics`, with help text saying what a non-zero
  value means rather than restating the name.
- The syslog listeners' `RateLimited`, `Oversize` and `Dropped` counters are exposed too — these
  count what the process refused before it ever became a countable event.
- The engine has no HTTP surface, so its DNS and SMTP listeners report their discard counters
  periodically, and **only when a counter has moved**. A healthy listener stays silent; one that
  starts refusing says so.
- **A guard test** fails when a counter is declared and not exposed. This is the part that lasts: the
  eight did not go missing at once, they accumulated one increment at a time, each added by someone
  who reasonably assumed the metrics surface already covered it.

## Impact

- Affected specs: `observability`
- Affected code: `internal/controlplane`, `cmd/openshield-engine`
- No proto change, no migration, no new dependency.
- Purely additive to `/metrics`. Existing metric names are untouched, so anything consuming them
  keeps working.

## Honest limits

- **Exposure is not alerting.** These become visible; nothing pages on them. Deciding thresholds is an
  operator's job and a routing rule, not a default this change should invent.
- **The engine's periodic report is a log line, not a metric.** Giving the engine an HTTP surface is a
  larger decision — it is the endpoint process, and opening a port on every endpoint is not a change
  to make as a side effect of adding observability.
