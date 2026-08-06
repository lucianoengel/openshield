# control-plane

## ADDED Requirements

### Requirement: The operator surface serves the entity graph and its risk

The operator surface SHALL serve the entity graph with the risk currently held for each entity, and SHALL
serve a single entity resolved from any one of its alias values.

#### Scenario: An entity with no recent alerts reports no risk rather than zero
- **WHEN** no alert within the window concerns an entity
- **THEN** its risk is reported as absent, not as zero

#### Scenario: An unknown value is distinguishable from an entity with nothing recorded
- **WHEN** a value naming no entity is requested
- **THEN** the surface reports that none was found, rather than returning an empty entity

#### Scenario: A malformed window is refused
- **WHEN** the risk window is not a positive duration
- **THEN** the request is refused rather than silently given the default
