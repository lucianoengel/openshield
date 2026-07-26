# typed-config Specification

## Purpose
Declared, validated, introspectable configuration (PLAT-5). Every field is declared once and used for both
reading and describing, so the schema is a projection of what the binary actually reads — the property
that lets a future UI (PLAT-1) drive configuration without drifting from it. Secrets are never readable
back, validation errors are field-scoped and reported together, and sources are layered with an explicit
precedence.


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
