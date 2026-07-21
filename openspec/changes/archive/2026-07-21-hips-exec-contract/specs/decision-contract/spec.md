# decision-contract delta

## MODIFIED Requirements

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
