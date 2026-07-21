## Context

The endpoint walking skeleton is `internal/engine`: `engine.New(worker, policy,
ledger, ...)` builds a `core.Dispatcher` with a `classifyStage{worker}` + the OPA
policy stage, wires `OnOutcome = core.NewAuditSink(ledger).Record`, and `enforce()`
dispatches a Decision to a registered `TargetedEnforcer` with the file path as
target. `cmd/openshield-engine` (D62) is the connector that feeds it fanotify
events. The endpoint proved observe-first, deferred inline file blocking (D1/D49).

D69 settled the network CONTRACT: `NetworkSubject` (metadata only), `ACTION_REDIRECT`,
and a fitness test showing a network Event flows the UNCHANGED dispatcher. This
change builds the network `engine`-equivalent and the flow enforcer, proven without
sockets — the connector (a real HTTP proxy listener) is a later increment.

## Goals / Non-Goals

**Goals:**
- A network pipeline assembly that classifies a request body in-process, decides
  via the existing dispatcher + policy, audits, and (observe-only by default)
  dispatches to a flow enforcer keyed by flow_id.
- A flow enforcer (BLOCK/REDIRECT) proving the target-string enforcer interface
  generalises to a second domain via a pluggable flow table.
- Prove it end to end WITHOUT sockets or Postgres (fake ledger, fake flow table).

**Non-Goals:**
- Real sockets, a socket-backed flow table, live-connection drop/reset/redirect
  (N1.2); TLS interception + do-not-intercept list (N1.3).
- Moving body classification into the sandboxed worker (D71 follow-up).
- Any proto/core/dispatcher change — all reuse.

## Decisions

**The gateway classifies the BODY before the pipeline, not inside a classify stage
reading the Event.** The endpoint's classify stage reads the file PATH out of the
Event and hands it to the worker; the resulting path is IN the Event. A network
body is NOT in the Event (D10/D29 — the Event carries metadata only), so the body
cannot come from `State.Event`. The Gateway therefore holds the plaintext body and
runs a per-request body-classify stage (a closure over THIS request's bytes) that
calls `internal/classify` and puts a content-free `LocalClassification` on
`State.Classification` — then the EXISTING policy stage runs unchanged. The
dispatcher is built per `Process` call with `[body-classify, policy]` stages and
`OnOutcome = NewAuditSink(ledger).Record`; per-request dispatcher allocation is
cheap for a skeleton and noted as an optimisation point, not hidden.

**The boundary-safe projection is copied from the engine, deliberately.** The
classification handed to the policy is `{detector_type, confidence, count}` per hit
occurrence with NO matched text — the same shape the engine builds from worker hits
and the same shape allowed off-host (D10/D29). The body bytes never enter the Event,
the Decision, or the ledger row.

**The flow enforcer reuses `core.TargetedEnforcer` — flow_id is the target.** A file
enforcer resolves `target` to a path; the flow enforcer resolves `target = flow_id`
to a live connection. Because the live connection does not exist yet (no sockets),
the enforcer resolves the flow_id through a `FlowTable` interface (`Block(flowID)` /
`Redirect(flowID)`); the socket-backed implementation is N1.2. `Capabilities()`
advertises `{BLOCK, REDIRECT}` (the network verdicts); `Enforce` without a target
errors (a flow enforcer cannot act without a flow_id); `EnforceTarget` switches on
the action. This proves the enforcement DISPATCH — `CanEnforce` gates the action,
the target flows through — with the table as a seam.

**Observe-only is the default (D1), same as the engine.** `Gateway.enforce()` walks
registered enforcers; with none registered it dispatches nothing — the Decision is
still classified and audited. Registering a flow enforcer turns enforcement on for
the actions it advertises. Enforcement outcome (success or failure) is audited;
failure is high-severity, never silent (D14).

**Body classification runs IN-PROCESS here — a caveat, not a silent assumption.**
The endpoint parses attacker-controlled file bytes in a seccomp-sandboxed,
network-denied worker (D29/D35) precisely because a parser bug in a privileged /
network-capable process is RCE. The gateway is network-capable (it is a proxy), so
classifying untrusted bodies in-process is the SAME danger. For the skeleton the
body is classified in-process; production MUST move body classification to a
sandboxed worker (reusing the worker seam). Recorded as D71, a required hardening
follow-up, documented in the proposal and decisions — not assumed safe.

## Risks / Trade-offs

- **In-process body parsing is a known gap** (above). Mitigated for now by scope
  (skeleton, no live traffic) and recorded as D71. Shipping it silently would repeat
  the "mechanism proven in isolation, false of the assembled system" failure the
  audit round caught — so it is stated loudly.
- **Per-request dispatcher allocation.** Acceptable for a skeleton; a production
  proxy would build the stage graph once and pass the body via a request-scoped
  seam. Noted, not premature-optimised.
- **`flow_id`/host/path are sensitive** (DPIA scope of egress monitoring, per D69).
  This change carries them because the policy needs them; the telemetry projection
  (what crosses to the server) is a separate boundary-safe step designed with the
  real proxy, not here.
