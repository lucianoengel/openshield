

## Purpose

Configuration as a declared, validated, introspectable model rather than scattered env reads. Settings
are split into BOOTSTRAP (env or file) and DYNAMIC (the database is the only source), so a host and a
console can never silently disagree; the environment does not override a dynamic setting, except through
a per-field break-glass that applies AND announces itself. A change is a revision with an author and a
diff, validated when made, applied without a restart, with secrets never stored in the store and never
readable back.

## Requirements

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

### Requirement: A break-glass override applies and is announced
A dynamic field named in `OPENSHIELD_BREAKGLASS` SHALL take its environment value, and the process SHALL
announce every such override at startup as well as reporting its origin on the configuration surface.

The scope split's promise is a conjunction, and only the conjunction is safe: an override that does not
apply is a broken incident tool, and one that is not reported recreates the silent console/host
divergence the split exists to refuse. Until D317 the process announced only the HARMLESS case — a
dynamic env value being IGNORED — and said nothing about the consequential one, so a host deliberately
not running what the console shows was visible only to somebody who thought to query `/config`. That
asymmetry is backwards: during an incident, "why is this host different" is asked of logs first.

#### Scenario: The override applies, is logged, and is shown with its origin
- **WHEN** a dynamic field is named in break-glass and set in the environment, and a different value is
  stored in the database
- **THEN** the process honours the environment value, announces the active override at startup, and
  `/config` reports that field with a break-glass origin and the effective (not stored) value

#### Scenario: An unnamed field is not overridden
- **WHEN** break-glass names one field and a DIFFERENT dynamic field is also set in the environment
- **THEN** the stored value wins for the unnamed field
- **AND** the scenario asserts WHICH value was loaded rather than waiting for silence: the loader runs on
  a tick, so "nothing happened yet" is not evidence, and a mutation making break-glass a general escape
  passed against the version that waited

### Requirement: The configuration schema is derived from what the code reads

The system SHALL expose a machine-readable description of every configuration field — its key, kind,
default, description and constraint — and that description SHALL be derived from the same declarations the
binary reads its values from. A description maintained separately from the reading code drifts from it,
and the drift is silent: a form offers a setting the binary ignores, and nobody finds out until the
setting fails to take effect.

#### Scenario: Every readable field is described
- **WHEN** the configuration schema is requested
- **THEN** it contains an entry for every field the binary reads, with its key, kind, default and
  description

#### Scenario: A field cannot be read without being described
- **WHEN** a field is added to the configuration
- **THEN** it appears in the schema without a second declaration being written

<!-- restored from 2026-07-26-plat5-typed-config -->

### Requirement: Secret values are never readable back

A field declared as a secret SHALL report only whether it is set. Its value MUST NOT appear in the schema,
in any effective-configuration output, or in logs. An interface that can render a stored credential back
into a form field is an exfiltration path, and it is one that looks like a feature.

#### Scenario: A secret is reported as set, not shown
- **WHEN** effective configuration is printed and a secret is configured
- **THEN** the output states that it is set and does not contain the value

#### Scenario: A secret is absent from the schema
- **WHEN** the schema is requested
- **THEN** no secret's value appears in it

<!-- restored from 2026-07-26-plat5-typed-config -->

### Requirement: Validation reports every problem, scoped to its field

Validation SHALL report ALL invalid fields together, and each problem SHALL name the field, the offending
value and the constraint it violated. Failing on the first problem makes an operator fix configuration one
boot at a time, and an unscoped error cannot be shown next to the input that caused it.

#### Scenario: Several invalid fields are all reported
- **WHEN** more than one field is invalid
- **THEN** every one is reported, each naming its field and constraint

#### Scenario: An invalid value fails the boot
- **WHEN** a configured value violates its constraint
- **THEN** startup fails with that error rather than substituting the default

#### Scenario: A malformed value is not silently defaulted
- **WHEN** a duration or integer field cannot be parsed
- **THEN** it is an error naming the field, not a fall back to the default

<!-- restored from 2026-07-26-plat5-typed-config -->

### Requirement: Sources are layered with an explicit precedence

Configuration SHALL be resolved from ordered sources, with environment taking precedence over a file and a
file over the declared default. The source set SHALL be an interface so a source can be added without
changing how any value is read.

#### Scenario: Environment overrides a file value
- **WHEN** a field is set in both a file and the environment
- **THEN** the environment value is used

#### Scenario: An unset field takes its declared default
- **WHEN** a field appears in no source
- **THEN** its declared default is used and reported as coming from the default

#### Scenario: The origin of a value is reportable
- **WHEN** effective configuration is inspected
- **THEN** each value states which source supplied it

<!-- restored from 2026-07-26-plat5-typed-config -->
