# Fix: the classify stage errored on non-file events (regression exposed by D133)

## Why

The engine's classify stage derived the file path from the event's filesystem target and
**errored** when it was empty (`classify: event carries no resolvable path`). That was correct
while only fanotify FILE events entered the engine — but D133 wired the DNS connector in, and a
DNS event has a *network* target and no file path. So every DNS event failed at the classify
stage and never reached policy → decide → audit: the D133 wiring produced events the engine
rejected. The D133 test only checked the Event reached the channel, not that `Process` handled
it — the "verified against its own assumptions" trap.

The pipeline was already designed to decide on non-file events: `buildInput` exposes network
metadata (`host`, `method`, `path`) and process metadata (`exec_path`, `args`) to the policy.
Only the classify stage never got the memo, because until D133 no non-file event exercised it.

## What Changes

- **`classifyStage` skips content classification for events with no filesystem target** — a DNS
  query, HTTP request, process exec, or USB insert carries no file *content* to scan, so it
  hands the policy an EMPTY classification and continues; the content worker is not called. The
  policy then decides on the event's metadata.
- **A file event that reaches classify with an empty path still errors** — the skip is pinned to
  genuinely non-file events, so it cannot mask a broken file event as "nothing to classify".

This corrects the `endpoint-engine` capability. No core interface change.

## Impact

- Affected specs: `endpoint-engine`
- Affected code: `internal/engine/engine.go` (classify stage), `internal/engine/engine_test.go`
  (a network event flows to a decision; a pathless file event still errors).
- Not in scope (stated): classifying a network event that DOES carry content (SMTP's message
  body) — that needs the body threaded via `ClassifyRequest_Content` and lands with the SMTP
  source wiring (a follow-up); the SMTP/syslog source wiring itself.
