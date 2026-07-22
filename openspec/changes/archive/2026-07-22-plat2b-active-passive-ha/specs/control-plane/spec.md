## ADDED Requirements

### Requirement: The singleton work runs under an active-passive leader lease

The control plane MUST run its singleton work — the telemetry consumer, the in-memory peer analytics,
and the periodic maintenance loops — under a leader lease so that at most ONE instance performs it at
a time (active-passive). Leadership MUST be held via a Postgres SESSION-scoped advisory lock on a
dedicated connection, so the single-holder guarantee is the database's and a leader that dies (its
connection drops) releases leadership automatically, without a time-to-live or heartbeat. A standby
instance MUST wait, acquiring leadership only when it becomes free, and MUST then run the singleton
work; on a graceful step-down the leader MUST release the lock explicitly so a standby can take over
promptly. A single deployed instance MUST become leader immediately and behave exactly as a
non-HA deployment.

#### Scenario: Exactly one leader, and a standby takes over on release
- **WHEN** two instances contend for leadership against the same database, and later the leader steps down
- **THEN** exactly one is elected while the other waits (never both), and when the leader releases the waiting instance is elected and runs the singleton work — a takeover, not a split-brain
