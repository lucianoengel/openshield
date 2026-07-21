# architectural-fitness Specification

## Purpose
The executable form of the zero-core-change claim: a capability added entirely from outside core flows an event end to end, core depends on no concrete capability, and the suite is labelled — in code and a test-guarded doc caveat — as necessary but NOT sufficient (D26).
## Requirements
### Requirement: A capability can be added without editing the core
Adding a Connector, Stage or Enforcer MUST require no change to `internal/core`. A test MUST
demonstrate this by defining a connector, a stage and an enforcer entirely outside core, wiring
them through the public contracts, and flowing an Event to a Decision.

The project's central bet is that the pipeline absorbs new capabilities as plugins. A test that
adds one using only core's public API — with the capability types existing nowhere in the shipped
tree — is the executable form of that claim: if it could be written, a capability needs no core
edit.

#### Scenario: An out-of-tree capability flows an event end to end
- **WHEN** a connector, stage and enforcer defined only in the test package are wired via the
  public core contracts and an Event is dispatched
- **THEN** it produces a Decision the test enforcer can act on
- **AND** the test imports nothing from any concrete capability package, so its mere compilation
  proves core alone suffices to extend the system

### Requirement: The core depends on no concrete capability
`internal/core` MUST NOT import any concrete capability package (connectors, enforcers, classify,
policy, store). A CI check MUST fail the build if it does.

If core cannot even name a capability, it cannot depend on one, and adding a capability cannot
require editing core. This is the machine-checkable core of the zero-core-change claim, the same
shape as the broker/database boundary already enforced.

#### Scenario: A capability import into core fails the build
- **WHEN** the dependency graph of `internal/core` is computed
- **THEN** it contains no capability package
- **AND** the check fails the build rather than warning, and a test confirms the check exists and
  runs so it cannot be quietly removed

### Requirement: The fitness test states that it is necessary but not sufficient
The fitness suite MUST record, where a reader and the CI cannot miss it, that a green result does
NOT validate the architecture — the test is gameable, and the real test of the claim is a
capability of a genuinely new shape (T-004), not a second like-shaped one.

D26 established this with a worked example: letting Policy query the analytics store directly
passes the diff-based test with zero core changes while destroying stage isolation. A fitness
test that presented itself as proof would manufacture exactly the false confidence the project
was built to avoid.

#### Scenario: The caveat cannot silently disappear
- **WHEN** the documentation reference recording the "necessary but not sufficient" verdict (D26 /
  the T-004 design) is checked
- **THEN** it is present
- **AND** a test asserts its presence, so the caveat cannot be dropped while the reassuring green
  check remains

#### Scenario: The known gaming vectors are guarded
- **WHEN** a capability attempts to reach another stage other than through the pipeline State, or
  an enforcer attempts to see classifier internals
- **THEN** the existing isolation guards (State carries no handles; the enforcer-isolation
  compile-fail) reject it
- **AND** the fitness suite references those guards so the boundary they defend is named as part
  of the fitness claim

### Requirement: The network data plane fits with only small additive core changes
Adding the network data plane MUST require only small, identifiable, additive core changes — a new
Event target variant, one closed action, and one validator entry — and MUST NOT require changes to the
dispatcher, pipeline State, Stage/Registry, the enforcer interface, the outcome sink, or the ledger,
proving the pipeline is genuinely data-plane-agnostic (the D26 claim).

#### Scenario: A network Event flows through the unchanged dispatcher and is decided and audited
- **WHEN** a network Event is run through the existing dispatcher with a network-classify stage and a
  policy stage that emits a network verdict
- **THEN** the Decision is produced and audited through the existing outcome sink, and a flow enforcer
  carries out the verdict through the existing enforcer interface
- **AND** a test demonstrates this with no change to the dispatcher, State, Stage, Registry, enforcer
  interface, outcome sink, or ledger

