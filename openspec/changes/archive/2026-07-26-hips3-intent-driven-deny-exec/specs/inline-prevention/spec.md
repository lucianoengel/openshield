## ADDED Requirements

### Requirement: An inline exec verdict may be driven by a coordinated-response intent

The system SHALL make the coordinated-response intent in effect for an execution's subject available to the
inline exec decision as typed policy CONTEXT, so a policy can refuse a contained entity's execution INLINE
rather than terminating the process after it has run.

The intent SHALL be delivered as context a policy consults, never as an instruction the gate executes. A
policy that does not read it SHALL be unaffected by any intent.

That property has an honest cost which SHALL NOT be described away: a deployment running a policy that never
reads the intent provides NO containment at the exec gate and reports nothing unusual.

#### Scenario: A contained entity's execution is refused inline
- **WHEN** a containment intent is in effect for an execution's subject and the policy reads it
- **THEN** the execution is refused by the kernel before the process runs

#### Scenario: A policy that ignores intents is unaffected
- **WHEN** a containment intent is in effect and the policy does not read it
- **THEN** the execution proceeds exactly as it would with no intent

### Requirement: The intent reaches policy as a closed value, never free text

The intent SHALL be exposed to policy as a member of the CLOSED response-intent vocabulary, together with a
flag distinguishing "no intent" from "an intent that says nothing". It SHALL NOT be carried as free text.

The enrichment context is deliberately a closed typed set rather than an open map, so that a compromised
control plane cannot influence decisions by inventing keys a policy happens to read; a free-text intent
would reopen exactly that door.

#### Scenario: The intent is a closed vocabulary member
- **WHEN** policy input is built for an execution whose subject has an intent
- **THEN** the intent appears as a closed-vocabulary value and a presence flag, and nothing free-form

### Requirement: A containment is liftable

The system SHALL allow an execution that was refused under containment to run again once no intent is in
effect for its subject — because none was issued, or because the intent expired.

A containment that could not be lifted would be a permanent quarantine.

#### Scenario: Lifting the containment restores execution
- **WHEN** the containment for a subject is no longer in effect
- **THEN** the same executable runs successfully

### Requirement: Intent consumption does not change the gate's fail-open rule

Consuming intents SHALL NOT alter the exec gate's behaviour when its evaluator is unavailable: a timeout,
crash or unreachable engine still ALLOWS the execution with a high-severity audit.

Containment therefore depends on a live engine, and that dependency SHALL be stated rather than implied
away.

#### Scenario: A dead engine still allows execution
- **WHEN** the engine is unavailable while a containment is nominally in effect
- **THEN** the execution is allowed and the fail-open is audited
