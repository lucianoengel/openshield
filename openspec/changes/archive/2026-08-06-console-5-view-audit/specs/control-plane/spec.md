## ADDED Requirements

### Requirement: An evidence-bearing read MUST be recorded by default, and an exclusion MUST be written down

An evidence-bearing operator read SHALL be recorded before the response is served, and a read that is NOT
recorded SHALL be one a named exclusion table exempts, carrying the reason and the residual it leaves. A
read is evidence-bearing when what it returns — or narrows to — is what the platform holds about a person,
an entity, or an endpoint's activity.

The failure this removes is not the missing rows, it is the shape that produced them: recording written
by hand in each handler is recording that a new handler silently does not do. The read surface grew from
four routes to more than twenty, and eleven of the new ones record nothing. So the default SHALL be to
record, and NOT recording SHALL be the case that requires somebody to write a sentence a reviewer can
disagree with.

#### Scenario: A read surface added without a decision is recorded
- **WHEN** an operator read route is served and no exclusion names it
- **THEN** the view is recorded, rather than the route being unaudited by omission

#### Scenario: An exempt route states its reason
- **WHEN** a read route is exempted from recording
- **THEN** the exemption carries the reason and the residual exposure it accepts

#### Scenario: An exclusion names a route that exists
- **WHEN** a path carries a recording decision
- **THEN** that path is one the server actually mounts, so no decision applies to nothing

#### Scenario: The fleet-aggregate and detection reads are recorded
- **WHEN** an operator searches the fleet aggregate, the detection queue, the ingested third-party logs,
  the incident queue, or the entity graph
- **THEN** each read leaves a record naming the operator and the route

### Requirement: A view record MUST say what was read, not only that a read happened

A recorded view SHALL carry the route served and the query that selected the rows, in addition to the
viewer and the time.

"An operator read the event search" does not distinguish a dashboard refresh from a targeted search for
one named endpoint, and the boundary this record defends is exactly that distinction.

The stored query SHALL be canonicalised so two spellings of one search compare equal, and SHALL be
bounded in length — it is operator-controlled text written into an audit table on every request, and an
unbounded one is a write amplification an authenticated insider controls. A truncated query SHALL be
marked as truncated, so no reader mistakes a partial record for a complete one.

#### Scenario: A recorded read names its route and filter
- **WHEN** an operator runs a filtered search over an audited surface
- **THEN** the recorded view carries the route and the filter that selected the rows

#### Scenario: An over-long query is bounded and says so
- **WHEN** a query longer than the stored bound is served
- **THEN** the recorded query is truncated and carries a marker saying it was truncated

#### Scenario: Two spellings of one search record identically
- **WHEN** the same filter is sent with its parameters in a different order
- **THEN** the recorded query is the same string

### Requirement: A read that cannot be recorded MUST NOT be served

When recording a view fails, the read SHALL be refused and the underlying handler SHALL NOT run.

This is the invariant that makes the record worth having: an operator who can make the recording fail and
still receive the evidence has an unaudited read. The cost is accepted and stated — a database that can
serve reads but not accept the record takes the read surface down, which is the correct direction of
failure for an accountability control.

#### Scenario: A failing record refuses the read
- **WHEN** the view record cannot be written
- **THEN** the request is refused and no evidence is returned

#### Scenario: The handler does not run
- **WHEN** the view record cannot be written
- **THEN** the wrapped read handler is not invoked at all

### Requirement: The view audit MUST have a retention window and a recorded purge

Recorded views SHALL be purged past a configured retention window by the same leader-only retention work
that purges the fleet aggregate, and each purge SHALL be recorded as a retention compliance event naming
the view table as its target.

The table stores raw, non-pseudonymised operator identities and, once a console exists, grows faster than
any other. Every other subject-adjacent store in the product is bounded and its purge provable; an
unbounded permanent record of everything every operator looked at is not a posture this product can
defend.

The default window SHALL exceed the fleet-aggregate retention default: an accountability record that
expires before the evidence it describes leaves nothing to check a disputed read against.

#### Scenario: Views past the window are removed
- **WHEN** the retention purge runs with a window
- **THEN** views older than the window are deleted and views inside it are kept

#### Scenario: The purge is provable to an auditor
- **WHEN** the view-audit purge runs
- **THEN** a retention compliance event is recorded naming the view table, the rows removed, the cutoff
  and the policy

#### Scenario: The purge runs in the shipped server
- **WHEN** the shipped control-plane binary holds leadership with a view-audit window configured
- **THEN** the recorded views past that window are purged without operator intervention

### Requirement: A subject access report MUST state who looked at the subject

The data-subject access report SHALL include the recorded views that named the subject, as a count and
the span they cover.

"Who has been looking at me" is the question a data-subject request most obviously asks of a view audit,
and the report compiled every other subject-keyed store while omitting this one.

The report SHALL NOT claim more than it holds: it covers reads that NAMED the subject, and a fleet-wide
search that happened to include them is recorded as a fleet-wide search rather than as a view of them.

#### Scenario: A subject's report counts the views that named them
- **WHEN** a subject access report is compiled for a subject that has been viewed
- **THEN** the report carries the number of views naming that subject and the span they cover

#### Scenario: An unviewed subject reports zero rather than omitting the fact
- **WHEN** a subject access report is compiled for a subject nobody has viewed
- **THEN** the report carries a count of zero
