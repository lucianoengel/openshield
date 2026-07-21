# heartbeat delta

## ADDED Requirements

### Requirement: Overdue agents trigger a deduplicated notification
An agent that has gone overdue (silent past the threshold) MUST trigger a notification, and MUST be
notified only ONCE per silence — not on every check — by deduplicating against the set of already-
notified overdue agents; an agent that reports again MUST be eligible to alert on a future silence.

#### Scenario: A newly-overdue agent notifies once
- **WHEN** the overdue check runs and an agent is overdue that was not previously notified
- **THEN** exactly one notification is delivered for it, and a subsequent check delivers none

#### Scenario: A recovered agent can alert again
- **WHEN** a previously-overdue agent reports again and later goes silent again
- **THEN** it is eligible to notify once more
