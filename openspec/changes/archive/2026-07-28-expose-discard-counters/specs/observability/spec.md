# observability

## ADDED Requirements

### Requirement: Every declared discard counter MUST be observable

Every counter the control plane maintains MUST be exposed on the metrics surface, and a counter that
is declared without being exposed MUST fail the build.

A counter exists so that a discard is not silent. One that is incremented and never rendered provides
the illusion of that property while delivering none of it — and the failure is invisible precisely
because the counter looks present in the code.

#### Scenario: A counter that is not exposed fails the guard

- **WHEN** a counter is added to the control plane and not rendered on the metrics surface
- **THEN** the guard MUST fail, naming the counter

#### Scenario: External-log ingest discards are visible

- **WHEN** an external log is dropped because neither parser accepted it, or its persistence failed
- **THEN** the count MUST be readable from the metrics surface

### Requirement: Listener admission refusals MUST be observable

A listener MUST make reachable its counts of messages refused by admission rate limiting, refused for
exceeding the line bound, and dropped for failing to parse.

Without them a deployment cannot distinguish a quiet estate from one whose traffic is being refused at
the door — on the ingest path that carries another system's evidence.

#### Scenario: Rate-limited messages are counted and visible

- **WHEN** a listener refuses messages under its admission rate limit
- **THEN** the refused count MUST be observable

#### Scenario: A listener that is not configured reports no metric

- **WHEN** no listener of a given kind is running
- **THEN** its counters MUST be absent rather than reported as zero

### Requirement: An endpoint process MUST report a listener that starts discarding

A process with no metrics surface MUST report its listeners' discard counters when they increase, and
MUST NOT report them when they have not.

#### Scenario: A discarding listener is reported

- **WHEN** an endpoint listener's discard counter increases
- **THEN** the process MUST report it

#### Scenario: A healthy listener stays silent

- **WHEN** no discard counter has increased since the last report
- **THEN** the process MUST report nothing
