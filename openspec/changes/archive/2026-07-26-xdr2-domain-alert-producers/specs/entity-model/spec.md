## ADDED Requirements

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
