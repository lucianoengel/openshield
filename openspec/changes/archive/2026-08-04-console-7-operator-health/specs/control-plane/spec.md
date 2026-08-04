## ADDED Requirements

### Requirement: An operator MUST be able to see whether the process answering them is working

The control plane SHALL serve a health report to an authenticated operator at the lowest operator tier,
carrying at minimum: whether this process holds leadership, whether the message broker is connected,
whether the database is reachable, the schema skew between the binary and the database, the
telemetry-ingest repair counters, and the newest external ledger anchor.

Without it an empty incident queue is indistinguishable from broken ingest, which is the most common way
a deployment is judged to have detected nothing when in fact it observed nothing.

Each fact SHALL be read at request time. A cached health answer reports the moment it was last convenient
rather than the present one, which is the failure mode this surface exists to remove.

The report SHALL NOT require a credential other than the operator's own. A health surface reachable only
with a second, separately-distributed token is one the console cannot render.

#### Scenario: An authenticated operator reads the health report
- **WHEN** an operator with the lowest operator tier requests the health report
- **THEN** it is served, and the facts it carries are gathered rather than defaulted

#### Scenario: An unauthenticated caller cannot read it
- **WHEN** a caller with no operator credential requests the health report
- **THEN** the request is refused, at the transport or at the operator gate

### Requirement: A process that does not hold leadership MUST NOT be reported as unhealthy

A health report SHALL state leadership as a fact and SHALL NOT treat its absence as a fault.

Only the leader runs the scheduled work, so a follower doing exactly what it should would otherwise be
reported as broken on every standby in a highly-available deployment — and a check that cries fault on
correct behaviour is a check people learn to ignore.

Leadership SHALL be reported from the election that actually governs the scheduled work, and SHALL be
cleared when leadership is lost. A stale claim of leadership is worse than no claim, because it is the
one an operator would act on.

#### Scenario: A follower reports no fault
- **WHEN** a process that does not hold leadership serves a health report
- **THEN** leadership is reported as not held, and no problem is raised on account of it

#### Scenario: The leader's claim comes from the real election
- **WHEN** the only instance of a deployment has been elected leader
- **THEN** its health report states that leadership is held

### Requirement: A health fault MUST state its consequence and MUST NOT contradict its own summary

A reported fault SHALL say what it costs the deployment, not only which condition was observed. Any
summary flag SHALL be derived from the list of faults, so the two cannot disagree.

A condition is already visible in the report's own fields; the list exists to tell an operator why they
should stop what they are doing. A summary that can disagree with the list beside it is one a reader will
trust over the list.

An empty fault list SHALL be serialized as an empty list, never as a null, so "healthy" and "we could not
tell" are distinguishable by a consumer that does not check.

#### Scenario: A healthy report carries an empty list, not a null
- **WHEN** a health report has no faults
- **THEN** its fault list is present and empty

#### Scenario: The summary agrees with the list
- **WHEN** a health report is served
- **THEN** its degraded summary is true exactly when its fault list is non-empty
