## Context

Pieces: `privileged.StartWorker`/`Worker.Classify` (IPC to the parser worker, returns
`[]DetectorHit`), `policy.Stage` (OPA), `core.Dispatcher` + `core.AuditSink` (Postgres ledger),
`Dispatcher.Logger`. check-agent-deps bans encoding/json from cmd/openshield-agent, so OPA can't
run there; the worker has seccomp no-network (D35), so Postgres can't run there. Hence a third
component.

## Goals / Non-Goals

**Goals:**
- `internal/engine` assembling classify-via-worker → policy → audit + logger; a cmd binary.
- One event end to end proven against the REAL worker binary + REAL Postgres → verifiable ledger row.
- Document the three-process shape and why.

**Non-Goals:**
- The fanotify front-end wired in (privilege-gated, documented); enforcement (Phase 2); the fleet
  transport wire.

## Decisions

### The classify stage bridges the worker to State, content-free
`engine.classifyStage{ worker *privileged.Worker }`. Given a `State` whose Event carries a file
path, it builds a `ClassifyRequest{Path: ...}`, calls `worker.Classify`, and turns the returned
`[]DetectorHit` (type + confidence + count) into a `LocalClassification` on the State — one
`LocalMatch` per hit, carrying detector type and confidence but EMPTY matched_text, because no
content crossed the IPC boundary (D29). The policy's input aggregates by type, so count is preserved
by emitting `count` matches per hit (or a single match with the count carried) — the policy sees
type + confidence + count, which is all it reads.

A worker error is a stage error (not a clean result) — the worker package already turns a classifier
crash into a response error, and the stage surfaces it, so a failed parse is auditable, never a
silent "nothing found" (the D17 principle).

### The engine owns the dispatcher and its lifecycle
`engine.New(worker, policyStage, ledger, logger)` builds a `Registry` (classify, policy), a
`Dispatcher` with the audit sink as `OnOutcome` and the logger set, and exposes
`Process(ctx, event) (*Decision, error)`. The worker is started once and reused (the IPC is
synchronous, one request in flight). `cmd/openshield-engine` starts the worker binary, opens the
ledger, loads/creates the signer (write-resume, D46), builds the engine, and processes events fed
to it (in Phase 1, from a simple source; the fanotify agent forwards them in production).

### End-to-end test uses the real worker binary and real Postgres
Build the worker binary, start it, open the ledger against Postgres, assemble the engine, and
Process an event for a file containing a seeded CPF. Assert: the returned Decision is ALERT, and the
ledger has a verifiable entry recording it. This is the walking skeleton. Skips loudly if Postgres
is unavailable; the worker build is part of the test (as the existing boundary test does).

### The three-process shape, documented
The privileged agent (fanotify + watchdog, no OPA/pgx) forwards events to the engine; the engine
(OPA + pgx, no CAP_SYS_ADMIN) runs the pipeline and calls the worker; the worker (parsers, no
network) classifies. check-agent-deps keeps the privileged agent clean; the worker's seccomp keeps
it network-free; the engine is the only one holding both OPA and pgx, and it is unprivileged.

## Risks / Trade-offs

- **A third binary.** It is forced by the constraints (OPA vs the agent's ban; Postgres vs the
  worker's seccomp), not chosen. Documented so it reads as a consequence. The alternative (relaxing
  the agent's dep ban to admit OPA) would gut D29.
- **The classify stage flattens hits to content-free matches.** Deliberate — content must not cross
  the boundary (D29); the policy only needs type + confidence + count, which survive.
- **fanotify front-end not wired.** Privilege-gated and covered elsewhere; the engine's input is a
  file-path event, exactly what fanotify yields. Stated.
- **Worker reused across events with a single in-flight request.** Matches the IPC's synchronous
  contract; concurrency is a later throughput concern, not a Phase-1 walking-skeleton need.
