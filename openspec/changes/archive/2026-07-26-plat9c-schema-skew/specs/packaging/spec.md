## ADDED Requirements

### Requirement: Schema skew is detected and reported

A binary SHALL compare the migrations it embeds against those the database has applied and report whether
it is behind, level, or running against a schema NEWER than it knows. The newer case arises whenever a
binary is rolled back after a migration, and it MUST NOT be silent: the binary is then reading a schema
whose changes it cannot know.

#### Scenario: A rolled-back binary reports the skew
- **WHEN** the database has more migrations applied than the binary embeds
- **THEN** the skew is reported, naming how many migrations the binary does not know

#### Scenario: A level binary reports no skew
- **WHEN** the applied and embedded migration counts match
- **THEN** no skew is reported

#### Scenario: Skew is observable without reading logs
- **WHEN** a binary is running against a newer schema
- **THEN** the condition is exposed as a metric

### Requirement: A newer schema does not prevent startup

A binary meeting a newer schema SHALL start. Refusing would make rollback impossible after any migration —
worse than the risk it avoids, and a direct contradiction of the requirement that a deployment can roll
back.

#### Scenario: Startup proceeds under skew
- **WHEN** the database schema is newer than the binary
- **THEN** the binary starts, having reported the skew
