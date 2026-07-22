# Design — network-content classification

## Content reaches the worker, not the Event

D10 keeps content out of the Event (it would otherwise cross to telemetry/audit); D29/D35 keep
content PARSING in the sandboxed worker, never the network-capable engine. Both hold here: the
SMTP body flows connector → engine → worker as inline `ClassifyRequest_Content`. The engine holds
the bytes only long enough to forward them; it runs no detector/parser on them, so the RCE surface
stays in the worker (which already bounds inline content with the same max-bytes ceiling as a file).

## The seam is engine-level, not core

`Dispatch(ctx, event)` takes only the Event, and adding content to the Event or the frozen `State`
would break the boundary or the core. Instead the classify stage holds a `*contentHolder` — a
mutable indirection the Engine also holds — so `SetContentResolver` can install a body source after
`New` without changing any core type. Default resolve is nil: network events are metadata-only, so
files and DNS behave exactly as before.

## Branch order preserves D134

The non-file branch first tries content (resolver yields bytes → worker-classify), then falls back
to the empty classification for a metadata-only event. A file event with a path classifies by path;
a file event without a path still errors. So the three D134 properties (DNS skips, empty
classification for metadata, pathless file errors) are preserved, and one property is added (SMTP
body classifies). The mutation that disables the content branch makes the SMTP body never reach the
worker — the test's "worker saw content" assertion fails.
