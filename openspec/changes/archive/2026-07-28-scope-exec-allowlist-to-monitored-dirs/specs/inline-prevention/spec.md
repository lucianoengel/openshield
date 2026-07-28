## ADDED Requirements

### Requirement: Application whitelisting is bounded by the monitored directories

Default-deny SHALL apply only to executions whose resolved path lies under a configured monitored
directory. An execution outside every monitored directory SHALL be permitted regardless of the
allowlist, because it was never in the scope the operator declared.

The bound is required, not merely desirable, because the kernel mark is BROADER than the configuration.
Exec-permission events are delivered only for a MOUNT mark — a directory inode mark does not deliver
them for files executed inside it — so the agent necessarily observes every execution on the mount. A
deny-list is unaffected by that breadth, since it refuses exactly what it names; an unbounded
default-deny refuses every executable on the filesystem.

Unbounded, the failure is also UNRECOVERABLE: stopping the agent requires executing a program, logging in
requires executing a shell, and both are refused. The system SHALL NOT be able to reach that state
through documented configuration.

An explicit deny-list SHALL remain unscoped. An enumerated list of binaries to refuse has a blast radius
equal to what it names, at any breadth; an implicit refusal of everything-not-named is safe only inside a
declared boundary.

#### Scenario: An allowlisted binary in a monitored directory executes

- **WHEN** application whitelisting is enabled and a binary named on the allowlist is executed from a
  monitored directory
- **THEN** the execution proceeds

#### Scenario: An unlisted binary in a monitored directory is refused

- **WHEN** a binary that is not on the allowlist is executed from a monitored directory
- **THEN** the execution is refused inline

#### Scenario: A binary outside every monitored directory is unaffected

- **WHEN** application whitelisting is enabled and a binary elsewhere on the same mount — a system
  utility, a shell, the tool needed to stop the agent — is executed
- **THEN** the execution proceeds, because it is outside the declared scope

#### Scenario: The deny-list keeps its reach

- **WHEN** a deny-listed binary is executed from outside every monitored directory
- **THEN** it is still refused, because an enumerated refusal is bounded by what it names

#### Scenario: The operator is told the real scope

- **WHEN** application whitelisting is enabled
- **THEN** the startup notice states the directories the default-deny applies to
