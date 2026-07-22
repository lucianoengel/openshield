# entity-model Specification

## Purpose
The cross-domain (XDR) entity model: a durable device ⋈ user graph keyed by the ONE canonical
pseudonym derivation (IDENT-1), so every domain's detections resolve to the same entity — the
foundation the XDR correlation lane sits on. An entity is an abstract asset; entity_aliases are its
names (a device's canonical pseudonym, a user's identity). Resolution is atomic under concurrency and
linking a device and a user merges their entities. Postgres is the system of record.


### Requirement: Alias resolution to a stable entity

The system SHALL resolve an alias — a `(kind, value)` such as a device's canonical pseudonym or a user's
identity — to a durable entity id, creating the entity on first sighting and returning the same id
thereafter. Resolution MUST be atomic under concurrency: two simultaneous resolutions of the same new
alias MUST yield exactly one entity, not two.

#### Scenario: The same alias always resolves to the same entity

- **WHEN** an alias is resolved twice
- **THEN** both resolutions return the same entity id

#### Scenario: The canonical pseudonym joins across domains

- **WHEN** one domain resolves a device by its canonical pseudonym and another domain resolves the same
  device by the same canonical pseudonym derivation
- **THEN** both resolve to the same entity id

#### Scenario: Concurrent first-sight resolutions create one entity

- **WHEN** the same new alias is resolved concurrently
- **THEN** exactly one entity is created and every caller receives its id

### Requirement: Linking a device and a user into one entity

The system SHALL link two aliases (a device and a user) to the same entity, merging their entities if
they were previously separate, so a device ⋈ user pair resolves to a single entity. After a link, both
aliases MUST resolve to the same entity id and no alias MUST be lost.

#### Scenario: Linking merges two separate entities

- **WHEN** a device alias and a user alias that resolved to different entities are linked
- **THEN** both aliases afterward resolve to one entity id and the other entity is emptied

#### Scenario: A link is idempotent

- **WHEN** two already-linked aliases are linked again
- **THEN** they still resolve to the same single entity id
