## ADDED Requirements

### Requirement: Correlation runs on a schedule, not only on request

The control plane SHALL materialize incidents on an interval, without an operator request, so a burst
becomes a raised and notified incident whether or not anyone is looking. Both the single-domain burst rule
and the cross-domain rule SHALL be materialized.

Only the elected leader SHALL run the loop: every replica correlating would multiply materializations and
the pages that follow them.

#### Scenario: An incident is raised with no operator request
- **WHEN** alerts that satisfy a correlation rule are recorded and the scheduled loop runs
- **THEN** an incident exists and a notification was delivered, with no request to the incidents endpoint
- **AND** the test FAILS if materialization only happens inside the request handler

#### Scenario: A non-leader does not correlate
- **WHEN** an instance that does not hold leadership runs
- **THEN** it does not materialize incidents

### Requirement: An incident has a forward-only, attributed lifecycle

An incident SHALL progress through `open → acknowledged → triaged → contained → closed`. A transition SHALL
record the operator who made it and when. A transition that skips forward SHALL be permitted; a transition
that moves BACKWARD or to an unknown state SHALL be refused.

Forward-only is deliberate: a lifecycle that can go backwards makes time-to-acknowledge and
time-to-resolve unmeasurable, and those metrics are the point of recording the lifecycle at all.

#### Scenario: An incident advances and records who advanced it
- **WHEN** an operator transitions an open incident to triaged
- **THEN** the incident's state is triaged and the transition names that operator and its time

#### Scenario: A backward transition is refused
- **WHEN** a transition is attempted from a later state to an earlier one
- **THEN** it is refused and the incident's state is unchanged
- **AND** the test FAILS if the transition is applied

#### Scenario: An unknown state is refused
- **WHEN** a transition names a state outside the lifecycle
- **THEN** it is refused rather than stored
