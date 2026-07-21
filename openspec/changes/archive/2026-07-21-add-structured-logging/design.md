## Context

`Dispatcher` has `report(ctx, s, o)` called on every terminal outcome, and `Dispatch` returns an
error on every failure path (stage failed, timeout, no-decision, not-recorded). Sentinel errors
exist: `ErrStageFailed`, `ErrNotRecorded`, `ErrReentry`, `ErrNoDecision`, plus ledger/transport
errors. Nothing logs structurally. `log/slog` is stdlib (Go 1.21+), so no dependency and no
core-deps violation.

## Goals / Non-Goals

**Goals:**
- Every terminal outcome logged with correlation id (event id), stage, kind, severity, category.
- A stable error-category taxonomy for countability.
- A test proving no failure path is silent in the logs.

**Non-Goals:**
- OTel/tracing (deferred); changing control flow; logging content; mandating a prod destination.

## Decisions

### Dispatcher takes an optional *slog.Logger
`Dispatcher.Logger *slog.Logger`. Nil-safe: a helper `d.log()` returns the logger or a
discard logger, so embedders and tests are not spammed by default. Logging happens in the outcome
switch and in `report`, not inside stages — the dispatcher owns the terminal-outcome vocabulary.

### Correlation id = event id
Every log line for an outcome carries `attr("event_id", state.Event.EventId)`. The pipeline is
per-event and in-process, so the event id correlates a decision, a classification and an audit
append without a separate trace id. Stated so the choice is deliberate, not a missing feature.

### Error taxonomy: a Category(err) function
`core.Category(err) string` maps a (possibly wrapped) error to a stable slug via `errors.Is`
against the sentinels: `stage_failed`, `timeout`, `not_recorded`, `reentry`, `no_decision`,
`ledger_unavailable`, `unreachable`, else `unknown`. Logged as `attr("category", ...)` and usable
by callers to count failures by class. `errors.Is` (not string matching) so wrapping is respected.

### Severity is logged at the slog level that matches
`SeverityHigh` → `slog.LevelWarn`+ (a timeout is operationally a warning that a Block became an
Allow, D17); `SeverityWarn` → Warn; info → Info. So a log level filter surfaces the loud events.

### Logs carry no content
Only ids, stages, categories, severities. Never the Event target, classification matches, or
decision reason beyond what is already non-sensitive. A test asserts a known content marker never
appears in a captured log. A log is a wire (D10).

## Risks / Trade-offs

- **Adding a field to the Dispatcher struct.** Optional and nil-safe; no behaviour change. The
  outcome switch gains log calls, tested to still return the same errors.
- **Category is a denylist-to-slug map.** A new sentinel needs a line here or it logs `unknown`;
  the test pins the known set so an unmapped-but-expected category is caught.
- **slog default level.** The discard default means silence unless an embedder wires a logger;
  cmd/* wire a stderr JSON handler. Documented.
- **Correlation id is not a trace id.** Fine for the in-process pipeline; cross-boundary tracing is
  T-028-not (OTel deferred). Stated.
