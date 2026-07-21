## ADDED Requirements

### Requirement: A new-shape capability is absorbed with one small, identifiable core change
Building peer-baseline UEBA MUST require exactly one small, identifiable core change — a Context
resolver hook on the dispatcher — and no more. With the hook unset, pipeline behaviour MUST be
unchanged (Context nil, observe-only).

D26's real test is whether the architecture absorbs a genuinely new-shape capability (stateful,
cross-entity) as a plugin or forces a sprawling core change. The honest answer, found in code: it
needs ONE named hook. That validates the small-change claim and disproves the zero-change one — and
pretending none was needed would be the overclaim the fitness test exists to expose.

#### Scenario: The core change is exactly the resolver hook
- **WHEN** peer-UEBA is built
- **THEN** the only core change is a `ResolveContext` hook on the dispatcher; the analyzer itself is
  entirely outside core
- **AND** the capability-boundary check still passes (core does not import the analyzer), and a nil
  resolver leaves behaviour unchanged

### Requirement: Peer-UEBA computes a cross-entity risk and feeds a Decision
The analyzer MUST compute a subject's risk RELATIVE to its peers (stateful, cross-entity) and
produce a Context the policy consults, so the peer signal can influence a Decision end to end.

Peer-baseline UEBA is the new shape precisely because it is stateful and cross-entity — a subject is
risky relative to OTHERS, not by a per-event rule. Proving it feeds a Decision through the Context
seam is proving the seam works for the shape it was designed for.

#### Scenario: An anomalous subject's peer risk escalates the Decision
- **WHEN** one subject's activity is far above its peers and a policy consults the peer risk score
- **THEN** its Context carries a high risk score and the policy escalates the Decision on that
  signal, even absent a PII hit
- **AND** a test drives the analyzer, the resolver, and a peer-aware policy and asserts the escalation

#### Scenario: Off by default leaves observe-only unchanged
- **WHEN** no resolver is configured
- **THEN** the Context is nil and behaviour is exactly Phase-1 observe-only
- **AND** a test asserts a nil resolver changes nothing
