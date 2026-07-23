## ADDED Requirements

### Requirement: Application whitelisting refuses a non-approved execution inline

When an execution allowlist is configured, the system SHALL refuse (block) a resolved execution whose
binary is not on the allowlist — default-deny — and SHALL allow an allowlisted execution. The deny-list
and behavioral checks SHALL apply BEFORE the allowlist, so an allowlisted binary that is also deny-listed
or behaviorally suspicious is still blocked (deny takes precedence over allow). An execution whose binary
cannot be identified (its path could not be resolved) SHALL be allowed rather than blocked (availability
over a false block), and the system's own executions SHALL remain exempt so whitelisting cannot deadlock
the agent. When no allowlist is configured, the system SHALL behave as deny-list-only (an unlisted
execution is allowed).

#### Scenario: A non-allowlisted binary is blocked when whitelisting is on
- **WHEN** an allowlist is configured and a process executes a binary that is not on it (path resolved)
- **THEN** the execution is refused inline

#### Scenario: An allowlisted binary runs
- **WHEN** an allowlist is configured and a process executes a binary on it
- **THEN** the execution is allowed (unless it is separately deny-listed or behaviorally suspicious)

#### Scenario: Deny takes precedence over allow
- **WHEN** a binary is on both the allowlist and the deny-list
- **THEN** the execution is refused

#### Scenario: No allowlist means deny-list-only
- **WHEN** no allowlist is configured and a binary is neither deny-listed nor behaviorally suspicious
- **THEN** the execution is allowed
