# endpoint-engine Specification

## Purpose
The walking skeleton: the unprivileged network-capable engine that assembles classify-via-worker → policy → decide → audit into one flow, proven end to end (seeded file → ALERT → verifiable ledger row). It is the third endpoint component, forced by the split (OPA cannot run in the privileged agent, Postgres cannot run in the sandboxed worker).
## Requirements
### Requirement: One event flows classify → policy → decide → audit end to end
The engine MUST assemble the real classify (via the unprivileged worker), policy, decision and
audit stages so that one event flows the whole pipeline and lands in a verifiable ledger entry. No
file content may cross the worker boundary into the pipeline.

Every piece is tested in isolation; the walking skeleton is the whole flowing as one, which is
where integration reality bites. Content-free classification (D10/D29) must survive the assembly —
the pipeline receives type + confidence + count, never matched text.

#### Scenario: A seeded file produces a verifiable audit row
- **WHEN** the engine processes an event for a file containing a seeded CPF, using the real worker
  binary and the real Postgres ledger
- **THEN** the decision is ALERT and the ledger has a verifiable entry recording it
- **AND** a test drives this end to end and verifies the chain

#### Scenario: No content crosses the worker boundary
- **WHEN** the classify stage receives the worker's result
- **THEN** the `State.Classification` it builds carries detector type, confidence and count only,
  with no matched text
- **AND** a test asserts the absence of content

#### Scenario: A worker failure is an auditable error, not a clean result
- **WHEN** the worker returns an error for an event
- **THEN** the pipeline terminates with a failure outcome that is logged and recorded, not a
  silent "nothing found"

### Requirement: The endpoint is three components, and the split is preserved
The endpoint MUST run as three components — the privileged fanotify agent, the unprivileged
network-capable engine, and the sandboxed parser worker — because OPA cannot live in the privileged
agent (encoding/json, D29) and Postgres cannot live in the sandboxed worker (network, D35). The
privileged agent MUST hold no parser/OPA dependency and the worker MUST hold no network.

The three-process shape is a consequence of the constraints, not a choice. Collapsing it would
break one of the boundaries the whole security model rests on.

#### Scenario: The privileged agent stays clean and the worker stays network-free
- **WHEN** the dependency checks run
- **THEN** `check-agent-deps` still passes for the privileged agent (no OPA/parsers) and the worker's
  seccomp still denies network — the engine is the only component holding both OPA and pgx, and it is
  unprivileged

