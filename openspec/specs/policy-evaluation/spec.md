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

### Requirement: A policy that matches nothing gets the stage's explicit, recorded default
If no policy rule produces a decision, the stage MUST emit an EXPLICIT decision carrying a reason that
says no rule matched — distinguishable in the ledger from a policy that affirmatively decided. This
MUST NOT be treated as a pipeline failure.

The outcome MUST be a property of the STAGE, not of the engine, because it is the stage that knows what
the decision is for:

- an OBSERVE-FIRST stage (the endpoint DLP pipeline) allows. An unmatched event there is the
  overwhelming majority of events — every ordinary file write on the host — and denying them would stop
  the machine rather than harden it.
- an ACCESS stage (the Zero-Trust gate) DENIES. An unmatched request there is a caller nobody
  authorized, and admitting it is the thing the gate exists to prevent.

Same engine, opposite correct answers. Before this, the engine allowed unconditionally and the access
proxy grants on ALLOW, so default-deny lived in the TEXT of the operator's Rego — a single
`decision := BLOCK if { not authorized }` line whose deletion, shadowing, or failure to keep up with a
new input shape silently converted a default-deny gate into a default-allow one, showing a reviewer only
a removed line they had to know was the whole security model.

Observe-only means the default is allow, but a silent allow and a reasoned "nothing matched" are
different records. The ledger must be able to tell "the policy considered this and let it pass" from
"no rule applied", and for an access stage it must further distinguish an authored denial from an
unmatched request — those are different operator problems, one a decision and the other a hole.

#### Scenario: No matching rule yields a reasoned allow in an observe-first stage
- **WHEN** a policy with no matching rule evaluates an Event
- **THEN** the Decision is ALLOW with a reason indicating no rule matched
- **AND** the outcome is a normal decision, not a failure

#### Scenario: No matching rule denies in an access stage
- **WHEN** an access policy has no rule matching the request
- **THEN** the Decision is a denial whose reason says no rule matched, so the gate refuses a caller its
  policy never mentioned

#### Scenario: An authored decision is never replaced by the default
- **WHEN** a rule DOES match
- **THEN** its own action and reason are what the Decision carries

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

### Requirement: Ready-made compliance policy packs are selectable
The policy layer MUST provide ready-made compliance packs (at least PCI, HIPAA, and GDPR) as
selectable policies, each alerting when a detector in that regulation's scope is present and allowing
otherwise, observe-only (alert, not block). Selecting a pack MUST COMPOSE it WITH the default policy,
never replace the default — so the default's protections (behavioral process alerting and the
strong-detector alert) remain in force while a pack is enabled. Selecting an unknown pack MUST be an
error, never a silent fallback to a permissive policy, and the identity of the composed bundle
(the default plus each selected pack) MUST be stamped on the resulting decision.

#### Scenario: A pack alerts on its scope and an unknown pack is refused
- **WHEN** a compliance pack evaluates data in its regulatory scope, data outside its scope, and a binary is configured with an unknown pack name
- **THEN** the in-scope data alerts, the out-of-scope data is allowed by that pack, and the unknown pack name is refused rather than silently applying a permissive policy

#### Scenario: The default's protections survive pack selection
- **WHEN** a pack is enabled and an input matches a default protection outside that pack's scope — a suspicious process-behavior score, and separately a checksum-backed CPF
- **THEN** each still ALERTs (the behavioral alert and the strong-detector alert are not lost), because the pack composes with the default rather than replacing it

### Requirement: Composed policies combine under a most-restrictive-wins data-verb lattice

The policy layer MUST, when more than one module is active (the default plus one or more packs and an
optional operator custom module), evaluate each module independently over the same input and combine
their decisions under a total, most-restrictive-wins ordering of the data-plane verbs:
`ALLOW < ALERT < REDIRECT < ENCRYPT_LOCAL < QUARANTINE_LOCAL < BLOCK` (QUARANTINE_LOCAL outranks
ENCRYPT_LOCAL). The composed decision MUST be the highest-ranked candidate, carrying that candidate's
reason and confidence. The process-control verbs `DENY_EXEC` and `KILL_PROCESS` MUST NOT be part of
this lattice, and a COMPLIANCE PACK that yields a process-control verb MUST be rejected as an error —
a pack MUST NOT be able to escalate to killing or denying a process. The composition MUST NOT weaken
determinism: identical input MUST still yield an identical composed decision.

#### Scenario: The most-restrictive verb across modules wins
- **WHEN** two active modules decide different data-plane verbs for the same input (for example one ALLOW and one BLOCK, or one ALERT and one QUARANTINE_LOCAL)
- **THEN** the composed decision is the more-restrictive verb (BLOCK over ALLOW; QUARANTINE_LOCAL over ALERT), with that module's reason

#### Scenario: A compliance pack cannot escalate to a process-control verb
- **WHEN** a compliance pack is composed whose decision yields `KILL_PROCESS` (or `DENY_EXEC`)
- **THEN** composition fails with an error rather than allowing the pack's process-control verb to take effect

#### Scenario: A single policy behaves exactly as before
- **WHEN** only one module is active (just the default, or a single explicitly-built policy)
- **THEN** the composed decision equals that module's decision unchanged — composition of one member is the identity

### Requirement: An access policy is proven to deny an unknown principal before it is used

Loading a module as an ACCESS policy SHALL evaluate it against a canonical principal carrying no
identity, no role and no device posture, and SHALL FAIL when that principal is ALLOWED.

This covers what a no-match default cannot. A module that allows unconditionally, or whose predicate is
vacuously true when the fields it reads are absent — `role != "banned"` reads like a denylist and admits
every caller whose role could not be resolved — MATCHES, so no default fires. Such a policy is not
incomplete; it is wrong, and it admits everyone who can complete the handshake.

The check SHALL run at LOAD, not at first request: the failure mode of a Zero-Trust gate must be "does
not start", never "starts and admits everyone".

The canonical principal SHALL be assembled by the same code that assembles a real request's policy
input. A probe evaluating a shape the policy never actually sees passes for the wrong reason, and the
input shape has gained fields repeatedly.

#### Scenario: A policy admitting an unknown principal is refused
- **WHEN** a module offered as an access policy allows a request with no identity, role or posture
- **THEN** loading fails, naming the reason, and the component does not start

#### Scenario: A policy that merely says nothing still loads
- **WHEN** an access policy authorizes some callers and is silent about the rest
- **THEN** it loads, because it never admits an unknown principal — the no-match default answers for the
  callers it does not mention

<!-- from secc-access-default-deny -->
