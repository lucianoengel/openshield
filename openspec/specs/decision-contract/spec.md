# Decision Contract

## Purpose

What the policy engine emits and the only thing an enforcer is permitted to see. Explainable to an investigator (reason, policy identity), opaque about detection (no classifier, pattern or matched content). The action set is closed so that a compromised control plane cannot express an exfiltration instruction.

> Synced from change `add-event-decision-contract` on 2026-07-20.
> Implemented in `internal/core`. The invariants below are enforced by tests
> (`schema_test.go`, `privacy_test.go`, `validate_test.go`, `compile_test.go`),
> each mutation-tested — a schema test that never fails is indistinguishable from
> no test.
## Requirements
### Requirement: The action set is closed and typed
`Decision.action` SHALL be a closed protobuf enum whose only members are `ACTION_UNSPECIFIED`,
`ACTION_ALLOW`, `ACTION_ALERT`, `ACTION_BLOCK`, `ACTION_QUARANTINE_LOCAL` and
`ACTION_ENCRYPT_LOCAL`. It SHALL NOT be a string, a free-form identifier, or a structure
carrying parameters such as a destination, URL, command or file path.

This is the constraint that makes "the server coordinates, it does not control" architectural
rather than aspirational (D14). An open action surface would let a compromised or malicious
control plane distribute a policy whose action is "upload this file to a URL" — an instruction
indistinguishable, at the enforcement point, from the platform's own legitimate telemetry.
A closed enum makes that unexpressible rather than merely forbidden.

#### Scenario: No parameterised action can be expressed
- **WHEN** the Decision message definition is inspected by a schema test
- **THEN** `action` is an enum, and no sibling field carries a URL, host, path or command
- **AND** the test enumerates the permitted enum members, so adding a new action requires
  editing the test — a deliberate speed bump on the most security-sensitive field in the system

#### Scenario: Unknown action values are rejected, not ignored
- **WHEN** a Decision arrives with an action value outside the known enum members
- **THEN** it is rejected and the rejection is recorded
- **AND** it is NOT silently treated as `ACTION_ALLOW` or `ACTION_UNSPECIFIED`

### Requirement: Decisions carry confidence, not certainty
`Decision` SHALL carry a confidence score in the range [0.0, 1.0] alongside its action.
Consumers SHALL NOT treat a Decision as a boolean verdict.

Classification is noisy by nature — the reference implementation the project benchmarks against
reports roughly 22.7% precision on person-name detection. A contract that models decisions as
certain would push that noise silently into enforcement (D4).

#### Scenario: Confidence is mandatory
- **WHEN** a Decision is constructed without an explicit confidence value
- **THEN** validation fails; there is no implicit default of 1.0

#### Scenario: Confidence is bounded
- **WHEN** a Decision carries a confidence outside [0.0, 1.0]
- **THEN** validation fails

### Requirement: Decisions are explainable without exposing detection internals
`Decision` SHALL carry a human-readable reason, the identifier and version of the policy that
produced it, and a stable decision ID. It SHALL NOT carry the classifier identity, the pattern
or regex that matched, model internals, or matched content.

Investigators need to know *why* a decision was made; enforcers must not. Keeping both in one
message and relying on consumers to ignore fields would make the separation a convention
(CrowdSec model).

#### Scenario: A Decision is explainable
- **WHEN** an investigator retrieves a recorded Decision
- **THEN** they can see the action, confidence, reason, and the policy ID and version

#### Scenario: Detection internals are absent from the message
- **WHEN** the Decision message definition is inspected
- **THEN** no field carries a classifier ID, pattern, model reference or matched substring

### Requirement: Enforcers receive only the Decision
The enforcement interface SHALL accept a `Decision` and nothing else. It SHALL NOT accept the
originating `Event`, the `Classification`, or any handle from which they could be retrieved.

#### Scenario: Enforcer isolation is enforced at compile time
- **WHEN** a hypothetical enforcer implementation attempts to reference a Classification or
  Event type
- **THEN** compilation fails
- **AND** this is proven by a test package that is expected NOT to compile, asserted in CI —
  not by a comment stating the intent

### Requirement: Phase 1 records decisions without acting on them
During Phase 1 the pipeline SHALL record every `Decision` to the audit path and SHALL NOT
invoke any enforcer (D1). The contract is defined in full now; only its execution is deferred.

#### Scenario: A block decision is recorded, not executed
- **WHEN** policy evaluation produces `ACTION_BLOCK` in a Phase 1 deployment
- **THEN** the Decision is written to the audit path
- **AND** the underlying operation proceeds unimpeded
- **AND** no enforcer is invoked

<!-- Added by change `add-agent-process-boundary` (2026-07-20). -->

### Requirement: Decisions record the enrichment context version
`Decision` MUST carry a `context_version` identifying the enrichment Context it was evaluated
against, empty when no Context applied.

Replay cannot reproduce a Decision without it: re-running an Event against today's context would
legitimately produce a different answer, and an audit trail whose entries cannot be reproduced
is not evidentiary. The field was added before any consumer existed because retrofitting one
into a hash-chained ledger means a migration and a break in chain continuity.

#### Scenario: Replay compares the context version
- **WHEN** a recorded Decision is replayed
- **THEN** the comparison includes `context_version`
- **AND** replaying against a different context version is reported as divergence rather than
  silently accepted

#### Scenario: Phase 1 records an empty context version
- **WHEN** a Decision is produced with no Context present
- **THEN** `context_version` is empty rather than absent-and-defaulted

### Requirement: The closed action set includes a network redirect verdict
The closed action set MUST include a REDIRECT verdict (send to a coaching/justification destination)
and it MUST be accepted by Decision validation; block-versus-reset is an enforcement MODE, not a
distinct verdict, and MUST NOT be a separate action — keeping the action vocabulary closed and small
so a compromised or mistaken policy source cannot express an open-ended action (D14).

#### Scenario: A REDIRECT decision validates; the vocabulary stays closed
- **WHEN** a policy emits a REDIRECT decision
- **THEN** validation accepts it as a member of the closed action set
- **AND** a test asserts REDIRECT validates and that no drop/reset action was added (mode, not verdict)


### Requirement: The action set is closed and widened only by deliberate decision
The Decision action set MUST remain a closed enum — a policy MUST NOT be able to express a
free-form or parameterized command. Adding an action MUST require a deliberate edit to every
closed-set guard (the validator, the policy name map, and the pinned enum test), not merely
a new proto value. The process-control verbs DENY_EXEC and KILL_PROCESS are part of the set,
each a distinct enforcement capability; a process-exec event MUST flow through the unchanged
dispatcher and be enforceable via the existing targeted-enforcer interface keyed by pid.

#### Scenario: A process-exec event is decided and validated under the closed set
- **WHEN** a process-exec event flows through the dispatcher and a policy emits KILL_PROCESS
- **THEN** the decision is audited and validates under the closed action set, and is carried out by the existing targeted enforcer via the pid, with no core interface changed
