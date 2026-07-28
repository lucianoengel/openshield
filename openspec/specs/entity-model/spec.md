# entity-model Specification

## Purpose
The cross-domain (XDR) entity model: a durable device ⋈ user graph keyed by the ONE canonical
pseudonym derivation (IDENT-1), so every domain's detections resolve to the same entity — the
foundation the XDR correlation lane sits on. An entity is an abstract asset; entity_aliases are its
names (a device's canonical pseudonym, a user's identity). Resolution is atomic under concurrency and
linking a device and a user merges their entities. Postgres is the system of record.

## Requirements

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

### Requirement: Kind-agnostic alias lookup

The entity store SHALL provide a lookup that resolves an entity by an alias VALUE across all alias
kinds, and that CREATES NOTHING when no alias matches. It is the primitive a consumer uses when it holds
an identifier but not the kind under which another domain already registered it — the device⋈user case,
where one domain knows a subject as a user and another knows the same entity as a device.

The lookup SHALL be read-only: a miss returns "not found", never a newly minted entity or alias. This is
what distinguishes it from resolve-or-create and makes it safe to call speculatively before falling back
to a kind-specific resolve.

#### Scenario: A value registered under another kind resolves
- **WHEN** a user alias `U` exists and a lookup is performed for the value `U` without naming a kind
- **THEN** the lookup returns the entity id that the user alias points to

#### Scenario: A miss creates nothing
- **WHEN** a lookup is performed for a value with no alias of any kind
- **THEN** it reports not-found
- **AND** no new entity or alias row exists afterwards

#### Scenario: A linked pair resolves to one entity from either value
- **WHEN** device `D` and user `U` have been linked into one entity
- **THEN** a kind-agnostic lookup for `D` and one for `U` return the SAME entity id
