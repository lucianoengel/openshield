# policy-evaluation Specification

## Purpose
The Decision stage: a local Rego policy (D6) evaluated on a restricted capability set — no network, clock or randomness — so decisions are deterministic and replayable, distributed policy is safe-by-construction, and only the closed typed action set can become a Decision.
## Requirements
### Requirement: The policy engine cannot reach the network, the clock, or randomness
The policy engine MUST be instantiated with a restricted capability set that excludes network,
time and randomness builtins. A policy that references an excluded builtin MUST fail to load,
with an error naming the problem, rather than evaluating.

This is what makes "the server coordinates, it does not control" enforceable rather than
aspirational: when policy distribution arrives, a pushed policy still cannot make a network call,
read the clock or use entropy — the capability set is the boundary, not a human reading the
policy. It is also what makes decisions deterministic, and it removes an SSRF/exfiltration
primitive (`http.send`) from every endpoint.

#### Scenario: A policy that calls the network is rejected at load
- **WHEN** a policy references `http.send` (or any network builtin) is loaded
- **THEN** loading fails with an error identifying the forbidden capability
- **AND** a test asserts this by attempting to load such a policy, so a regression that widened
  the capability set would be caught

#### Scenario: A policy that reads the clock is rejected at load
- **WHEN** a policy references `time.now_ns` (or any clock/randomness builtin) is loaded
- **THEN** loading fails
- **AND** the test asserts BEHAVIOUR (load fails), not the allowlist's contents, so it still
  guards after an OPA upgrade adds new builtins

### Requirement: Identical input produces an identical Decision
Evaluating the same Event against the same policy MUST produce Decisions that are equivalent on
every field a replay compares. Non-deterministic fields (`decision_id`, `decided_at`) are set
outside the policy and excluded from that comparison.

Determinism is the precondition for the audit trail being an investigation tool: a recorded
Decision that cannot be reproduced cannot be explained. The capability restriction is what
guarantees it — a policy with no clock and no randomness is a pure function of its input.

#### Scenario: Re-evaluation reproduces the Decision
- **WHEN** the same Event is dispatched through the policy stage twice
- **THEN** the two Decisions satisfy `DecisionsEquivalent`
- **AND** a test asserts it, pinning determinism against a future non-deterministic regression

### Requirement: Only actions in the closed set can become a Decision
The stage MUST map the policy's action to the typed `Action` enum through an explicit table and
MUST reject any action the enum does not define. A missing or unknown action MUST NOT become an
ALLOW.

The closed action set (D14) is what stops a compromised or careless policy expressing an action
the enforcer contract never defined — "upload to URL" arriving as an action string. A policy that
names a bogus action is a failed Decision, surfaced, not a silent allow.

#### Scenario: An unknown action is a failure, not an allow
- **WHEN** the policy returns an action name that is not in the `Action` enum
- **THEN** the stage returns a failed outcome naming the bad action
- **AND** it does not substitute ALLOW, because "the policy is broken" and "the policy allowed"
  demand different responses

#### Scenario: Every enum action round-trips
- **WHEN** the action mapping table is exercised
- **THEN** each defined `Action` value has exactly one name and maps back to it
- **AND** a test pins the table so adding an enum value without mapping it fails

### Requirement: A policy that matches nothing is an explicit, recorded allow
If no policy rule produces a decision, the stage MUST emit an explicit ALLOW carrying a reason
that says no rule matched — distinguishable in the ledger from a policy that affirmatively
allowed. This MUST NOT be treated as a pipeline failure.

Observe-only means the default is allow, but a silent allow and a reasoned "nothing matched" are
different records. The ledger must be able to tell "the policy considered this and let it pass"
from "no rule applied".

#### Scenario: No matching rule yields a reasoned allow
- **WHEN** a policy with no matching rule evaluates an Event
- **THEN** the Decision is ALLOW with a reason indicating no rule matched
- **AND** the outcome is a normal decision, not a failure

### Requirement: Confidence comes from classification and is never certainty
The Decision's confidence MUST derive from the classification evidence and MUST NOT be reported
as 1.0. The policy consumes detector confidence and count as thresholds.

Classification is noisy (D4). A Decision that reports certainty pushes that noise silently into
whatever consumes the Decision. The confidence must travel with it.

#### Scenario: The Decision carries a sub-certain confidence
- **WHEN** a Decision is produced from a classification hit of confidence < 1.0
- **THEN** the Decision's confidence is < 1.0
- **AND** a test asserts no code path emits a Decision with confidence 1.0


### Requirement: Policy can decide identity-aware authorization, and absent posture fails closed
The policy input MUST expose the identity, role, and device posture (including the presence flag) as a
boundary-safe closed projection of the Context, so a policy can make identity-aware authorization
decisions. A policy MUST be able to deny access when device posture is absent (an untrusted or tampered
device), and to deny a device that is present but not compliant.

#### Scenario: A compliant identity is allowed and an untrusted device is denied
- **WHEN** an identity-aware policy evaluates a compliant device for an authorized role
- **THEN** it allows; and when the device reports no posture, or reports non-compliant, it denies

### Requirement: The policy can decide on the requested service for microsegmentation
The policy input MUST expose the requested service host, method, and path for a network event, so a
policy can make per-service (and per-endpoint) authorization decisions. Exposing these to the local
in-process policy MUST NOT change what crosses the host boundary — telemetry still redacts the URL path.

#### Scenario: A policy authorizes a role to a specific service
- **WHEN** a policy conditions on the event host and the identity role
- **THEN** it can allow a role to one service host and deny it another

### Requirement: A process event's behavioral verdict is a policy input, decided observe-safe
The policy input for a process event MUST include a behavioral verdict (a score and the
LOLBin/lineage/encoded-command signals) derived from the event's exec metadata, so a policy can
decide on process behavior. The behavioral analysis MUST run on metadata only (no content), and the
POLICY — not the detector — MUST choose the action from the closed set. The shipped default policy
MUST ALERT (not terminate) on a suspicious score, and MUST NOT let the behavioral rule fire on a
non-process event.

#### Scenario: A suspicious process alerts and a benign one is allowed
- **WHEN** the default policy evaluates a process event whose behavioral score is suspicious, a benign process event, and a clean file event
- **THEN** the suspicious process is ALERTed (not terminated), the benign process and the file event are ALLOWed, and the behavioral rule does not fire on the file event
