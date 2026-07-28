# Design

## The guard is the actual fix

Rendering eight counters is the smaller half. They accumulated one at a time, each added by someone
who reasonably assumed the surface already covered them — and it will happen again the next time a
counter is added, unless something refuses it.

So a test reflects over the `Server` struct, collects every `atomic.Int64` field, and requires each to
appear in the metrics output. A new counter that is not rendered fails the build.

Reflection rather than a hand-maintained list, deliberately: a list is a second thing to forget, and
forgetting it looks exactly like the bug being fixed.

Counters that should genuinely not be exposed — if any ever exist — will need an explicit opt-out with
a reason next to it, which is the point. Making the omission deliberate and visible is the whole
mechanism.

## Help text says what a non-zero value MEANS

`openshield_cef_dropped_total` with help "CEF drops" is a metric nobody can act on. The existing
metrics already do this well — `openshield_notify_unrouted_total` explains that "a non-zero value
means the routing table has a hole" — and the new ones follow it. An operator seeing the number for
the first time, at 3am, should not have to read the source to know whether it matters.

## Listener counters are read through the listener the server already holds

`RunCEFSyslog` and `RunCEFSyslogStream` construct their listeners locally. The server keeps a
reference so the metrics handler can read the counters, published atomically so a metrics scrape that
races startup reads zero rather than nil-panicking.

Both listeners are optional; when neither is configured, the metrics are absent rather than zero.
Reporting `rate_limited=0` for a listener that does not exist is a different claim from not running
one, and a dashboard cannot tell them apart.

## Only reporting movement, in the engine

A periodic log line that fires unconditionally becomes noise and gets filtered, which turns a signal
into a silence with extra steps. The engine reports a listener's counters only when one has increased
since the last report — so an endpoint says nothing until it starts discarding, and then says so every
interval until it stops.

That direction is deliberate: the cost of a missed report is an unnoticed gap in visibility, and the
cost of a repeated one is a duplicated line.

## What this does not do

It does not alert. It does not choose thresholds. It does not give the engine an HTTP surface —
opening a port on every endpoint is a decision about the product's attack surface, not a side effect
of adding a counter.
