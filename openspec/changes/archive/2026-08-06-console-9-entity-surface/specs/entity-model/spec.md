# entity-model

## ADDED Requirements

### Requirement: The entity graph can be read, not only resolved

The entity store SHALL provide enumeration of entities with their aliases, and resolution of one alias
value to its entity and all of that entity's other aliases.

Every existing operation answers "what is the id for this name". None can answer "what does the platform
know", so the coalescing the model performs has been unobservable to operators.

#### Scenario: An entity is returned with every name it is known by
- **WHEN** a value that names an entity is looked up
- **THEN** the entity is returned with all of its aliases, not only the one searched for

#### Scenario: An entity with no aliases is still reported
- **WHEN** an entity exists with no aliases
- **THEN** it is returned with an empty alias list rather than omitted

### Requirement: Reading the graph does not modify it

Resolution for READ SHALL NOT create an entity when the value is unknown.

The ingest path creates on first sight, which is correct for ingest. A read that did so would make the
graph grow by being looked at, and every mistyped search would leave a permanent empty node.

#### Scenario: An unknown value creates nothing
- **WHEN** a value that names no entity is looked up
- **THEN** no entity is created and the lookup reports that none was found
