# durable-notification-dedup Specification

## Purpose
Persisting delivered notification ids so the SIEM-12 'page exactly once' idempotency survives a
restart/failover, fail-open on a database outage. Distinct from the alert-correlation dedup_key: this
is a delivery-idempotency ledger keyed by the notification id.


### Requirement: Notification idempotency survives a restart

The system SHALL persist the id of each emitted notification so that a logical alert re-detected within
the dedup window is delivered EXACTLY ONCE even across a process restart or failover — not re-paged
because the in-memory dedup state was lost. Recording SHALL be atomic (a concurrent or post-restart
re-emit of the same id is recognized as a duplicate).

#### Scenario: The same alert is not re-paged after a restart
- **WHEN** a server delivers a notification, then a fresh server (same database) emits the same logical alert within the window
- **THEN** the fresh server suppresses it and does not deliver a second page

#### Scenario: A same-process re-detection still pages once
- **WHEN** the same logical alert is emitted twice in one process within the window
- **THEN** it is delivered once and the duplicate is counted as deduped

### Requirement: The durable dedup fails open

The durable dedup layer SHALL be additive: when the database is unavailable (or no database is
configured), the system SHALL fall back to the in-memory idempotency decision and STILL deliver the
alert. A missing durable layer SHALL NEVER cause a page to be dropped.

#### Scenario: A database error does not drop a page
- **WHEN** the durable dedup insert fails (database unreachable)
- **THEN** the notification is still delivered (fail-open) and the failure is logged

### Requirement: The dedup ledger stays bounded

The system SHALL prune persisted notification ids older than the dedup window so the dedup ledger does
not grow without bound. An id need only outlive its window for the idempotency guarantee to hold.

#### Scenario: Aged ids are pruned
- **WHEN** the retention prune runs for ids older than the window
- **THEN** those ids are removed and no longer suppress a genuinely new later occurrence
