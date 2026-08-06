## ADDED Requirements

### Requirement: A recorded view MUST name the route it recorded

Every view written to the audit SHALL carry the route served. A recording call that cannot name a route
SHALL be refused, as a recording call with no viewer already is.

The empty route is not spare capacity: the migration that introduced the column declares that `''` means
"recorded before the route was captured". A live handler writing `''` makes the reads it records
indistinguishable from historic rows, so a query for that route returns nothing forever — and the routes
that did it were the five highest-sensitivity ones, because those are the reads whose handler knows a
subject the URL does not carry.

#### Scenario: A route audited by its own handler records its route
- **WHEN** a read is recorded by the handler that serves it rather than by the recording layer
- **THEN** the recorded view carries that handler's route alongside the subject it resolved

#### Scenario: A view recorded without a route is refused
- **WHEN** a view is recorded with no route
- **THEN** the recording is refused, so no live read can produce a row that reads as historic

### Requirement: A route recorded by its own handler MUST be proven to record

For every route the recording layer skips because its handler records instead, an automated check SHALL
prove that the handler still contains the recording call.

The recording layer skips those routes unconditionally, on the strength of a table entry. Removing the
call from the handler leaves the route unaudited with every test passing — which is the shape this
control was built to remove, reproduced inside the table that replaced it.

#### Scenario: A handler that stopped recording fails the build
- **WHEN** the recording call is removed from a handler the recording layer skips
- **THEN** a check fails naming that route, rather than the route becoming silently unaudited

#### Scenario: The data-subject access report records its own access
- **WHEN** an operator compiles a data-subject access report
- **THEN** the access is recorded with the route and the subject before the report is returned

### Requirement: A read mounted on the operator surface MUST pass through the view audit

Every mount on the served operator surface SHALL pass through the recording layer, or SHALL be named in
an allowlist carrying the reason it does not.

The recording layer is applied once, by hand, to a handler that ~37 mounts then share. A mount written
without it is unaudited, every existing check passes, and the next planned route on this surface is a
bulk export — the read this control exists for.

#### Scenario: A new mount that skips the recording layer fails the build
- **WHEN** a route is mounted on the operator surface without passing through the recording layer
- **THEN** a check fails naming that mount, unless an allowlist entry states why it is exempt

#### Scenario: An allowlist entry names a mount that exists
- **WHEN** the allowlist names a mount
- **THEN** that mount exists, so no exemption applies to nothing

### Requirement: A refused audited read MUST be visible to the operator

When the recording layer refuses a read, the failure SHALL be logged with its cause, counted in an
exposed metric, and named as a problem by the process health report.

The refusal is correct — an unrecordable read must not be served — but it takes the whole operator read
surface down at once. The health report is itself exempt from recording, so without this it answers
"healthy" while every other route answers 500, and the surface built to say whether the process works is
the one surface that cannot see the outage.

#### Scenario: The health report names the outage
- **WHEN** audited reads are being refused because the view cannot be recorded
- **THEN** the health report reports the process as degraded and names the cause

#### Scenario: The cause is not discarded
- **WHEN** a view record fails
- **THEN** the underlying error is logged, rather than the request answering 500 with nothing recorded
  anywhere about why

### Requirement: A recorded query MUST be the filter that selected the rows

The query stored with a view SHALL identify the filter actually applied. Where a route is invoked by a
mutable reference to a stored filter, the record SHALL carry the resolved filter and not only the
reference.

Recording a saved search's NAME records a pointer that the operator population can rewrite or delete
afterwards, at a lower tier than the one that reviews the audit. An audit row whose meaning can be
changed after the fact by a party it constrains does not bound anything.

#### Scenario: Running a saved search records what it searched for
- **WHEN** an operator runs a stored saved search by name
- **THEN** the recorded view carries the resolved filter and its surface, not only the name

#### Scenario: A stored filter that does not resolve is still recorded
- **WHEN** an operator runs a saved search that does not exist or cannot be parsed
- **THEN** the attempted read is recorded, because an attempt is worth recording whether or not it
  returned anything

### Requirement: A stored query MUST remain decodable after truncation

A query truncated to the stored bound SHALL remain decodable by a reader that reverses the encoding
applied to it.

The stored form is percent-encoded, and a cut taken at an arbitrary byte can land inside an escape
sequence. A record that a reader cannot decode is not a partial record, it is an error — and this is the
column whose whole purpose is to say what was searched for.

#### Scenario: A truncation lands on an escape boundary
- **WHEN** a query is truncated at the stored bound
- **THEN** the stored value decodes without error, and still carries the marker saying it was truncated

### Requirement: Retention purges MUST run and fail independently, and a failing purge MUST be visible

Each retention purge on the scheduled retention work SHALL run regardless of whether another purge
failed, SHALL report its own outcome naming its own target, and a failure SHALL be counted and named by
the process health report.

A failure that skips the purges after it silently stops enforcing retention on stores nobody was looking
at, and reports the failure under the name of the first one. And a purge that has been failing for
months is otherwise indistinguishable from one that was never due: the compliance record shows the
absence of an event either way.

#### Scenario: One failing purge does not stop the others
- **WHEN** one retention purge fails during a scheduled run
- **THEN** the remaining purges still run and report their own outcomes

#### Scenario: A failing purge is named
- **WHEN** a retention purge fails
- **THEN** the failure is counted and the health report names retention as not being enforced

### Requirement: The view audit MUST be indexed by the column the subject report joins on

The recorded views SHALL be indexed on the column a data-subject access report filters by.

That report is the one read on this table with a statutory clock on it, its predicate is an equality on a
single column, and this change makes the table the largest in the deployment. An unindexed scan that
grows with every console page view is a response time that degrades exactly as the record it reports on
becomes worth reporting.

#### Scenario: The subject-keyed lookup is indexed
- **WHEN** the recorded views are queried by the subject a read named
- **THEN** the query is served by an index rather than by a scan of the whole table

## MODIFIED Requirements

### Requirement: A subject access report MUST state who looked at the subject

The data-subject access report SHALL include the recorded views that named the subject, as a count and
the span they cover, and SHALL state separately how many of those were the subject's own access
requests.

"Who has been looking at me" is the question a data-subject request most obviously asks of a view audit,
and the report compiled every other subject-keyed store while omitting this one.

The report SHALL NOT claim more than it holds: it covers reads that NAMED the subject, and a fleet-wide
search that happened to include them is recorded as a fleet-wide search rather than as a view of them.

Compiling the report is itself a recorded read of the subject, written before the report is built, so it
appears in its own total. The breakdown is what keeps that honest — without it a subject who asks twice
sees the number rise and cannot tell their own requests from an investigator's.

#### Scenario: A subject's report counts the views that named them
- **WHEN** a subject access report is compiled for a subject that has been viewed
- **THEN** the report carries the number of views naming that subject and the span they cover

#### Scenario: An unviewed subject reports zero rather than omitting the fact
- **WHEN** a subject access report is compiled for a subject nobody has viewed
- **THEN** the report carries a count of zero

#### Scenario: The subject's own requests are counted separately
- **WHEN** a subject access report is compiled after previous access requests for the same subject
- **THEN** the report states how many of the counted views were subject access requests, distinct from
  reads by investigators
