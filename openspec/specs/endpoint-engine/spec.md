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

### Requirement: The engine binary runs the assembled observe pipeline
The `openshield-engine` binary MUST run the observe path itself — opening the fanotify connector in
unprivileged notify mode (D52) over configured directories and processing each event through
classify → policy → decide → audit — rather than building the pipeline and idling. An engine
configured with no watch directories MUST refuse to start, so a running engine is never a silent
no-op.

Observe-only remains the default: the engine records Decisions and enforces nothing unless an
enforcer is registered (D1/D14). A classify failure is auditable, never a silent allow (D17). The
privileged permission-mode agent is not required for observe and remains deferred (D49).

#### Scenario: A file dropped in a watched directory flows to the ledger
- **WHEN** the running engine binary watches a directory and a file containing detectable PII is
  written there
- **THEN** the event is classified, evaluated, decided, and the Decision is recorded in the
  forward-secure ledger
- **AND** a BINARY-level test (building and running the actual engine + worker against real Postgres)
  asserts the ALERT entry appears — not a package-level test calling internal functions

#### Scenario: An engine with no watch directories refuses to start
- **WHEN** the engine binary is started with no watch directories configured
- **THEN** it exits with an error rather than running as a no-op that observes nothing
- **AND** a test asserts the refusal

### Requirement: The shipped binaries state their capability honestly
The shipped binaries and their docs MUST distinguish what runs from what is deferred: the observe
pipeline runs as the `openshield-engine` binary, while inline blocking / the privileged
permission-mode agent is deferred (D49). The `openshield-agent` stub MUST name itself the deferred
inline component and exit non-zero, not present as a healthy but silent service.

#### Scenario: The agent stub does not masquerade as a running service
- **WHEN** the `openshield-agent` stub is run
- **THEN** it identifies itself as the deferred privileged inline-blocking component, points to the
  engine for observe, and exits non-zero
- **AND** the README and CHANGELOG describe the observe path as running as a binary and inline
  blocking as deferred, with no wording implying the full privileged path ships today


### Requirement: The engine projects real detections to the control plane, opt-in
When a telemetry projector is configured, the engine MUST project each Decision — with its originating
Event — to the control plane after recording it locally, additively to the local ledger. It MUST NOT
project when no projector is configured (the default), and MUST NOT fail the request on a projection
error (the local forward-secure ledger is the system of record). The Event is projected as-is: its file
path is the file's identity needed for fleet investigation, and the subject is already pseudonymous.

#### Scenario: A detection projects its Event and Decision
- **WHEN** the engine processes a file event with a telemetry projector configured
- **THEN** it publishes the Event (retaining the filesystem path) and the Decision

#### Scenario: No projection without a projector
- **WHEN** the engine processes an event with no projector configured
- **THEN** nothing is projected and the single-host observe path is unchanged

#### Scenario: A projection failure does not fail processing
- **WHEN** the projector returns an error
- **THEN** processing still completes and the decision remains recorded locally

### Requirement: The engine binary registers file enforcers opt-in, observe-only by default
The engine binary MUST register its file enforcers only when enforcement is explicitly
enabled, and MUST remain observe-only by default — with enforcement off, a decision is
recorded but no file is touched. With enforcement on, a quarantine decision MUST move the
flagged file and audit the enforcement outcome; an encrypt enforcer MUST be registered when a
key is configured.

#### Scenario: Enforcement is opt-in and contains a flagged file
- **WHEN** the engine processes a flagged file with enforcement enabled, and separately with it disabled
- **THEN** enabled it quarantines the file and audits an enforced outcome, and disabled it leaves the file untouched

### Requirement: The engine runs an optional DNS source into the pipeline
The engine MUST be able to run the DNS query connector as an additional event source, enabled by
configuration. When enabled, it MUST bind the DNS listener and feed each parsed query — as a
network Event carrying the queried name and the source IP — into the same pipeline as file
events, so live resolution runs classify → policy → decide → audit. The DNS source MUST be
additive to file watching and observe-only (it produces events, it does not enforce), and its
producer MUST be tracked so the event stream is not closed while the source is still running.

The classify stage MUST handle an event that carries no file content (a network, process, or USB
event) by producing an empty classification and letting the policy decide on the event's
metadata, rather than failing the event. A file event that reaches the classify stage without a
resolvable path MUST still fail, so the content-free path cannot mask a broken file event.

#### Scenario: A live DNS query flows through the pipeline as a network event
- **WHEN** the engine has the DNS source enabled and receives a query datagram
- **THEN** a network event carrying the queried name and source IP is produced onto the engine's event stream, flows through classify (empty, content-free) → policy → decide → audit without error, and the source shuts down cleanly with the engine

#### Scenario: A pathless file event still fails
- **WHEN** a file event reaches the classify stage with no resolvable path
- **THEN** it fails rather than being waved through as content-free

### Requirement: The engine classifies network-carried content in the sandboxed worker
The engine MUST classify the content of a network event that carries a body (an SMTP message) by
sending the bytes to the sandboxed worker as inline content, WITHOUT placing the content in the
Event and without parsing it in the engine itself. The content source MUST be installable after
construction and default to none, so a network event with no content source remains metadata-only
(classified on its metadata), and a file event continues to classify by path (and a pathless file
event continues to fail).

#### Scenario: An SMTP body is classified in the worker while DNS stays metadata-only
- **WHEN** the engine processes a network event whose body is provided by the content source, and separately a network event with no content
- **THEN** the body is classified in the worker and the resulting decision is audited, while the content-less event is classified only on its metadata and a pathless file event still errors
