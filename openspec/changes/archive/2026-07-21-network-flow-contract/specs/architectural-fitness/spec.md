# architectural-fitness delta

## ADDED Requirements

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
