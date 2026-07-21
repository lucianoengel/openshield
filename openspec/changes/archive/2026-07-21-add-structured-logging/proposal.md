# Add structured logging and a stage-failure error taxonomy (T-028)

## Why

Full OTel span coverage is cut from Phase 1, but the agent still has to be debuggable, and — more
importantly for this project — every terminal outcome must be OBSERVABLE. The dispatcher already
never swallows an outcome (it returns errors and calls `OnOutcome`), but nothing LOGS them in a
structured, correlatable way. When a stage fails or times out on an endpoint at 3am, an operator
needs a log line that says which event, which stage, which category of failure — not a bare error
bubbling up. Silent-in-the-logs is a milder cousin of silent-in-the-audit, and the same principle
(D17: a failure must be loud) applies.

## What changes

**A structured logger (`log/slog`, stdlib — no dependency) threaded through the dispatcher.** Every
terminal outcome — decided, failed, timeout, no-decision — is logged with a correlation id (the
event id), the stage, the outcome kind, the severity, and the error where there is one. A timeout
and a failure log at their real severity (high for a timeout, D17), so a rising rate is greppable.

**An explicit error taxonomy.** The sentinel errors already exist scattered (`ErrStageFailed`,
`ErrNotRecorded`, `ErrReentry`, `ErrNoDecision`, the ledger/transport errors); this gives each a
stable, logged CATEGORY string so failures are countable by class, not just as free text. A log
consumer can alert on `category=not_recorded` without parsing prose.

**No silent swallow, asserted by test.** A test drives a failing stage, a timing-out stage, and an
unrecorded append, and asserts each produces a log line carrying the correlation id and the right
category — so a future refactor that dropped a log on one of these failure paths fails CI.

## What this does NOT claim or cover

- **It is not OTel / distributed tracing.** Cut from Phase 1 deliberately. `slog` gives structured,
  correlatable logs; spans across the agent↔control-plane boundary are later. The correlation id is
  the event id, not a trace/span id — stated so the simpler choice is deliberate.
- **It does not change control flow.** The dispatcher already returns every error and reports every
  outcome; this adds observability, not new behaviour. No fail-open/fail-closed decision changes.
- **It does not log payload content.** Logs carry ids, stages, categories and severities — never
  the Event's content, the classification matches, or anything the privacy model (D10) keeps off
  the wire. A log is a wire too.
- **It does not mandate a log destination or format in production.** The dispatcher takes a
  `*slog.Logger`; where it writes and at what level is the operator's configuration. The default is
  a no-op so tests and embedders are not spammed.

## Decisions

Depends on **D17** (a failure/bypass must be loud and countable), the existing dispatcher outcome
model (D25), and the sentinel errors already defined across core.

Establishes a small new decision: **every terminal pipeline outcome is logged structurally with the
event id as correlation id and a stable error-category, using stdlib `log/slog`; logs carry ids
and categories, never content, and OTel tracing remains deferred.**
