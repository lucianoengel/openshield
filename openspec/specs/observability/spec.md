# observability Specification

## Purpose
Structured logging of every terminal pipeline outcome via stdlib slog: correlation id = event id, a stable errors.Is-based category taxonomy, severity-matched levels, and NO content in logs (a log is a wire, D10) - so no failure path is silent and failures are countable by class. OTel tracing deferred.
## Requirements
### Requirement: Every terminal outcome is logged with a correlation id and category
The dispatcher MUST log every terminal outcome — decided, failed, timeout, no-decision, not-recorded
— with the event id as correlation id, the stage, the outcome kind, the severity, and a stable
error category. No failure path may be silent in the logs.

The dispatcher already never swallows an outcome, but an operator debugging an endpoint at 3am
needs a correlatable log line, not a bare error. Silent-in-the-logs is the milder cousin of
silent-in-the-audit, and the same rule applies (D17): a failure must be loud and countable.

#### Scenario: A failing stage logs with the correlation id and category
- **WHEN** a stage returns an error
- **THEN** a log line is emitted carrying the event id and category `stage_failed`
- **AND** a test captures the log and asserts both, so a refactor that dropped the log fails CI

#### Scenario: A timeout logs at high severity
- **WHEN** a stage times out
- **THEN** the log carries category `timeout` at a warn-or-higher level, so a rising rate is
  greppable (a timeout silently turns a Block into an Allow, D17)

#### Scenario: An unrecorded append is logged
- **WHEN** the audit append for an outcome fails
- **THEN** a log carries category `not_recorded`
- **AND** a test asserts it

### Requirement: The error taxonomy is stable and category-mapped by identity
A `Category` function MUST map an error to a stable slug by error IDENTITY (`errors.Is` against the
sentinels), not by string matching, so wrapped errors are categorised correctly and a log consumer
can count failures by class.

Free-text errors cannot be alerted on; a stable category can. Matching by identity rather than
substring means wrapping an error with context does not change its category — the category is a
property of what went wrong, not of how the message was phrased.

#### Scenario: Wrapped sentinels categorise correctly
- **WHEN** a sentinel error is wrapped with additional context and passed to Category
- **THEN** it returns the sentinel's stable slug
- **AND** a test covers each known sentinel and an unknown error (which maps to `unknown`)

### Requirement: Logs carry no content
Pipeline logs MUST carry only ids, stages, categories and severities — never Event content,
classification matches, or any value the privacy model keeps off the wire.

A log is a wire (D10). Emitting matched content or a file's data into a log would leak exactly what
the two-type classification split and the summary-only transport exist to prevent, through a
different pipe.

#### Scenario: A content marker never appears in a log
- **WHEN** an event carrying a distinctive content marker flows through and its outcome is logged
- **THEN** the marker does not appear in the captured log output
- **AND** a test asserts its absence


### Requirement: The control plane exposes operational counters as Prometheus metrics
The control plane MUST expose its operational counters — dropped, rejected, and gapped telemetry among them — in the Prometheus text exposition format at a metrics endpoint, reflecting the live counter values, with a HELP and TYPE line per metric. The endpoint MUST expose counts only, never subject or content.

#### Scenario: The metrics reflect the live counters
- **WHEN** the metrics endpoint is scraped
- **THEN** it returns the current counter values in valid Prometheus format

### Requirement: The metrics endpoint can require auth and warns on exposure
The metrics endpoint MUST support requiring a bearer token, rejecting a request without the exact
token (compared in constant time) with 401, because its counters leak operational tempo useful for
reconnaissance. When the endpoint is bound to an address reachable beyond loopback without a token
configured, the server MUST warn loudly at startup rather than exposing it silently.

#### Scenario: An unauthenticated request is refused and an exposed bind is flagged
- **WHEN** the metrics endpoint is configured with a token and receives a request without it, and separately is bound to a non-loopback address without a token
- **THEN** the tokenless request is refused with 401 while the correct token is served, and the exposed bind produces a loud startup warning

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
<!-- synced from expose-discard-counters -->
