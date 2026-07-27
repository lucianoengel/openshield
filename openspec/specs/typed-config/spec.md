

### Requirement: Configuration is split into bootstrap and dynamic scopes

Every field SHALL declare a scope. **Bootstrap** fields are read from the environment or a file only and
are limited to what a process needs to start and reach its database. **Dynamic** fields SHALL be read from
the database, which is their single source of truth, so that changing one changes it for the whole
deployment without touching a host.

#### Scenario: A dynamic field reads from the database
- **WHEN** a dynamic field has a stored value
- **THEN** that value is what the process honours

#### Scenario: A bootstrap field is not stored
- **WHEN** a write is attempted against a bootstrap field
- **THEN** it is refused, naming the field and its scope

#### Scenario: The bootstrap set stays small
- **WHEN** the bootstrap fields are enumerated
- **THEN** they are limited to connection, listening, identity and credential-location settings

### Requirement: The environment does not silently override a dynamic setting

An environment value for a dynamic field SHALL NOT take effect silently. It SHALL either be ignored and
REPORTED as an ignored override, or applied only under an explicit break-glass that is likewise reported.
A setting the console shows as one value while a host runs another, with no signal, is what makes a
fleet's configuration unanswerable.

#### Scenario: An environment value for a dynamic field is reported
- **WHEN** a dynamic field is set in the environment
- **THEN** the effective configuration reports it as an ignored override, and the stored value is used

#### Scenario: Break-glass is explicit and visible
- **WHEN** the documented break-glass is engaged for a field
- **THEN** the environment value applies AND the effective configuration reports it as an override

### Requirement: A configuration change is a revision with an author and a diff

Changing settings SHALL create a revision recording who made it, when, an optional note, and the previous
and new value of every key changed. The system SHALL support returning to a previous revision.

#### Scenario: A change records its author and diff
- **WHEN** settings are changed
- **THEN** a revision exists naming the author and, per key, its old and new value

#### Scenario: A revision can be rolled back
- **WHEN** a prior revision is restored
- **THEN** the settings return to that revision's values, recorded as a new revision rather than by
  erasing history

#### Scenario: A rejected change creates no revision
- **WHEN** any key in a change is invalid
- **THEN** no revision is created and no key is applied

### Requirement: A change is validated when it is made

A proposed value SHALL be validated against its field's declaration at the moment of the change, and an
invalid change SHALL be refused in full. Discovering an invalid value at the next restart means the
operator who typed it is not the person who finds out.

#### Scenario: An invalid value is refused at save
- **WHEN** a change contains a value that violates its field's constraint
- **THEN** the change is refused, naming the field and the constraint, and nothing is applied

#### Scenario: An unknown key is refused
- **WHEN** a change names a key that is not declared
- **THEN** it is refused rather than stored for a field nobody reads

### Requirement: Secrets are never stored in the configuration store

A field declared as a secret SHALL be refused by the configuration write path. Its value SHALL remain in
the environment or a file on the host. A backup of the configuration database must not be a backup of the
deployment's credentials.

#### Scenario: Writing a secret is refused
- **WHEN** a change names a secret field
- **THEN** it is refused, and the store contains no value for it

### Requirement: A committed change applies without a restart

A new revision SHALL take effect in a running process without restarting it, and periodic work SHALL use
the current value rather than one captured when it started.

#### Scenario: A running loop picks up a new value
- **WHEN** a revision changes a setting a running loop uses
- **THEN** the loop uses the new value on a subsequent execution, with no restart

### Requirement: A command reads every dynamic setting through the resolver

A command SHALL obtain the value of a dynamic setting from the configuration resolver, and SHALL NOT read
it from its process environment. The database-authoritative scope is a property of the WIRING, not of the
resolver alone: a resolver that correctly ignores an environment value is defeated entirely by a `main()`
that reads the environment directly, and a process that both announces it is ignoring a setting and then
obeys it misleads the operator reading its log more than silence would.

Scope is per binary. A key MAY be dynamic for a process that has a database and bootstrap for one that
does not; each command SHALL be evaluated against its own declared field set.

#### Scenario: A setting saved in the console reaches a running process
- **WHEN** a dynamic setting is saved and a process is started
- **THEN** the process behaves according to the saved value

#### Scenario: A dynamic setting in the environment does not take effect
- **WHEN** a dynamic setting is present only in a process's environment
- **THEN** the process does not act on that value, consistent with the notice it prints

#### Scenario: Configuration is loaded before it is used
- **WHEN** a process starts
- **THEN** the stored settings are loaded before the process decides what to start, so a saved setting
  does not depend on winning a race against a background refresh

#### Scenario: A new command cannot be exempt by omission
- **WHEN** a command exists that is not classified against a declared field set
- **THEN** the check fails rather than skipping it

### Requirement: An operator can change configuration through the product

The dynamic configuration store SHALL be writable through the product's own authenticated surface. A store
that is authoritative for a process's behaviour and can only be written with hand-issued SQL is not a
configuration system.

The surface SHALL report the effective values with their origins, expose the schema derived from the field
declarations, list the revision history with what each change replaced, and restore a prior revision.

#### Scenario: A change applies to a running process
- **WHEN** an operator saves a dynamic setting
- **THEN** it is recorded as a revision attributed to that operator, and the running process honours it
  without a restart

#### Scenario: A dynamic setting applies live or is not dynamic
- **WHEN** a setting is declared dynamic
- **THEN** changing it takes effect without a restart

#### Scenario: A rollback lengthens the history
- **WHEN** a prior revision is restored
- **THEN** the restoration is itself a new revision and no earlier revision is removed
