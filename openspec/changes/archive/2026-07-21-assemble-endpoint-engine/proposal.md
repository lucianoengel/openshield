# Assemble the endpoint engine — the walking skeleton (Direction 2)

## Why

Every piece of the observe pipeline exists and is tested in isolation: the classifier (in the
worker), the policy stage, the dispatcher, the audit ledger, the structured logger. Nothing
assembles them into a running whole where one event flows classify → policy → decide → audit and
lands in a verifiable ledger row. That assembly is the plan's headline Phase-1 outcome, and it is
where integration reality bites — the pattern that has surfaced a real bug in almost every ticket.

Assembling it also forces an architectural fact into the open: the pipeline needs OPA (which uses
`encoding/json`, BANNED from the privileged agent by `check-agent-deps`, D29) and Postgres (network,
BANNED from the seccomp-sandboxed worker, D35). So policy+audit cannot live in the privileged
fanotify agent OR the parser worker — they need a third, unprivileged, network-capable component.
That component is the **engine**, and naming it is part of this change.

## What changes

**A new `internal/engine` that assembles the real pipeline**, and a `cmd/openshield-engine` binary
that runs it. The engine wires:
- a **classify stage** that hands the file to the unprivileged worker over the existing IPC
  (T-006), receives detector hits (type + confidence + count — NO content crosses the boundary,
  D10/D29), and puts them on the pipeline `State`;
- the **policy stage** (the shipped Rego on its restricted capability set, D34);
- the **audit sink** appending to the Postgres forward-secure ledger (D30);
- the **structured logger** (D43), so every outcome is correlatable — this closes the third
  deferred seam (the logger into a live binary).

**One event flows end to end, proven against real infrastructure.** A test drives a file
containing a seeded CPF through the REAL worker binary and the REAL Postgres ledger: the worker
classifies it, the policy alerts, the decision is recorded, and the resulting ledger entry
verifies. This is the walking skeleton — the "one real event → tamper-evident audit row" the plan
describes, minus only the fanotify front-end.

**The three-process shape is made explicit.** The privileged agent (fanotify + watchdog) forwards
an event to the engine; the engine runs the pipeline, calling the worker for classification. The
engine holds OPA and pgx (fine — unprivileged, network-capable); the privileged agent holds
neither (D29 stays enforced); the worker holds parsers but no network (D35 stays enforced). The
split is preserved, and this change documents why there are three components, not one.

## What this does NOT claim or cover

- **It does not include the real fanotify front-end wired to the engine.** The fanotify loop needs
  CAP_SYS_ADMIN and is covered by the watchdog (T-011), the spike (T-005), and the agent
  process-boundary tests; wiring the privileged agent to forward events to the engine is a thin,
  privilege-gated step documented here. The engine is driven in the test by an event as fanotify
  would deliver it (a file path), which is exactly the engine's input.
- **It does not enforce.** Observe-only (D1): the policy alerts, nothing blocks. The enforcer
  contract (T-020) is proven separately; wiring an enforcer into the live engine is Phase 2
  (Direction 3).
- **No content crosses the worker boundary.** The classify stage receives detector hits, not
  `LocalClassification` (D29); the `State.Classification` it builds carries type + confidence +
  count, no matched text. Asserted, not assumed.
- **It is not the fleet path.** The engine writes the LOCAL forward-secure ledger (the evidentiary
  record); forwarding summaries to the control plane over the transport is a separate wire (T-023),
  not part of this assembly.

## Decisions

Depends on **D1** (local-first, observe-only), **D24** (in-process pipeline), **D29/D35** (the
privilege split the three-process shape preserves), **D30** (the ledger), **D34** (the policy),
**D43** (the logger), and **T-006** (the worker IPC).

Establishes a new decision: **the endpoint runs as THREE components — the privileged fanotify agent
(forwards events), the unprivileged network-capable ENGINE (classify-via-worker → policy → decide →
audit), and the sandboxed parser worker — because OPA (encoding/json) cannot live in the privileged
agent and Postgres (network) cannot live in the sandboxed worker; the split is preserved and the
three-process shape is a consequence of the constraints, not a choice.**
