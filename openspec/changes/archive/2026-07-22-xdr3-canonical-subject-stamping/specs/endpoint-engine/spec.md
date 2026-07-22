## ADDED Requirements

### Requirement: The engine attributes endpoint events with the canonical device subject

The system SHALL let the engine be configured with its device's canonical pseudonym, and, when so
configured, stamp that pseudonym as the `Subject` of any event lacking one (and a timestamp if missing)
before dispatch, then validate the event and reject one that is still invalid. The stamped subject MUST
be the same canonical derivation the gateway and posture use, so an endpoint event and a gateway request
for the same device carry the same subject.

#### Scenario: A connector event is stamped and passes validation

- **WHEN** a configured engine processes an event that has a target but no subject
- **THEN** the event is stamped with the engine's canonical device pseudonym and passes the event
  contract validation

#### Scenario: The stamped subject is the canonical device identity

- **WHEN** an engine configured for a device processes an endpoint event
- **THEN** the event's stamped subject equals the canonical pseudonym of that device's identity

#### Scenario: A still-invalid event is rejected

- **WHEN** a configured engine processes an event that, even after stamping, violates the contract (e.g.
  no target)
- **THEN** the engine rejects it with an error rather than processing it

#### Scenario: An unconfigured engine is unchanged

- **WHEN** an engine with no configured device subject processes an event
- **THEN** it behaves as before — no stamping and no added validation
