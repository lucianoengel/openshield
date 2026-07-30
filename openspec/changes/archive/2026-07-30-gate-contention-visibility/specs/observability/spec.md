## ADDED Requirements

### Requirement: The endpoint MUST report what it is discarding WHILE it is discarding

Counters for input the engine drops SHALL be reported on an interval for as long as the process runs, not
only when it stops. A counter that has not moved SHALL NOT be reported, so a healthy engine is silent.

Every discard path fires under CONTENTION, which is exactly when nobody will stop the process to find out.
Reporting only at shutdown means a busy endpoint loses evidence silently for as long as it stays up — and a
process that is killed or crashes never reports at all, so the load that caused the loss is also the reason
the report never arrives.

This SHALL cover the file-open gate as well as the ingest listeners: dropped audit rows, gated opens not
fully classified, and opens declined at the suppression ceiling.

#### Scenario: A running engine under load says so
- **WHEN** the open gate is discarding work because its queue is full
- **THEN** the engine reports it on the interval, while still running

#### Scenario: A healthy engine is silent
- **WHEN** no counter has moved
- **THEN** nothing is reported

### Requirement: A dropped classification MUST NOT become a dropped decision

When the gate cannot queue a full classification, it SHALL still return a verdict for every open.

Losing depth under load is acceptable and is recorded; losing the decision is not. An endpoint that began
refusing or hanging opens under load would be a far worse failure than one that classified less thoroughly,
because the open is held in an uninterruptible window.

#### Scenario: Every open is answered under load
- **WHEN** the async classification queue is full
- **THEN** each open still receives a verdict, and clean files are allowed

### Requirement: A discard path MUST be reachable in a test

Bounds whose overflow cannot be exercised SHALL be configurable enough to be reached.

An overflow path that cannot be reached is written once and never exercised again, and this one carries an
evidentiary consequence — a decision that is not in the ledger.

#### Scenario: The queue depth is configurable
- **WHEN** a deployment or a test sets the gate's async queue depth
- **THEN** that depth is used
