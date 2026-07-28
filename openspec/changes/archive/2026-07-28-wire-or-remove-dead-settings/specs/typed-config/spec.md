## ADDED Requirements

### Requirement: Every declared setting has a reader

A declared configuration setting SHALL be read somewhere in the product. A setting no code reads MUST be
removed from the declared surface rather than left in it.

The configuration schema is DERIVED from the declarations so that a surface cannot offer a field the code
never had. That guarantee does not cover a field whose reader was later deleted, and the failure is the
same one derivation exists to prevent: the surface offers it, an operator sets it, nothing happens, and
nobody finds out until an incident.

The check SHALL ignore mentions in comments, because a setting's name commonly survives in prose that
explains why it was retired — which is exactly the case that must be caught, not excused.

#### Scenario: A declared setting with no reader fails the check

- **WHEN** a setting is declared and no non-comment code reads it
- **THEN** the check fails, naming the setting

#### Scenario: A setting read only by a library still passes

- **WHEN** a setting is declared for a command but read inside a package that command uses
- **THEN** the check passes, because a binary's configuration surface includes what its libraries read

#### Scenario: A setting named only in a comment does not count as read

- **WHEN** a setting appears in the product solely inside comments
- **THEN** the check fails, because prose explaining a retired setting is not a reader

### Requirement: Durable notification dedupe ids are bounded

The durable notification-dedupe ledger SHALL be pruned on a schedule to the configured retention, so it
does not accumulate one row for every notification ever emitted.

An id only needs to outlive its dedupe window for the page-once guarantee to hold, so the retention is
several windows rather than one — pruning to exactly the window would risk re-paging an alert whose id
was removed a moment before it recurred.

#### Scenario: Ids older than the retention are removed

- **WHEN** the prune runs and dedupe ids older than the configured retention exist
- **THEN** they are deleted and the count removed is reported

#### Scenario: A recent id survives the prune

- **WHEN** the prune runs
- **THEN** an id emitted within the retention window remains, so a duplicate is still suppressed
