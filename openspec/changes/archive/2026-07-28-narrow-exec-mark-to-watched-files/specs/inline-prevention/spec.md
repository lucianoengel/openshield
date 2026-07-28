## ADDED Requirements

### Requirement: The kernel mark is no broader than the gate's semantics

The exec monitor SHALL choose its fanotify mark from the semantics of the configured signal, so that an
execution the gate does not police generates no event.

A SCOPED signal — application whitelisting, whose reach is the monitored directories — SHALL be marked
per-file over those directories. A GLOBAL signal — a deny-list naming binaries to refuse wherever they
run, a behavioural floor, or a pipeline verdict — SHALL keep the mount mark, because narrowing it would
reduce what those catch.

The distinction is required rather than an optimisation: every event costs the executing process a
round-trip while it is blocked, so a broad mark is a tax on every process launch on the host, paid for
executions the agent has already decided are out of scope.

The system SHALL NOT rely on a directory mark with child events for exec permissions. It is not
available — the kernel refuses that combination for exec-permission events — and the refusal SHALL be
recorded by a test rather than by a comment, because it has been rediscovered twice.

#### Scenario: A scoped gate produces no event for an execution outside its directories
- **WHEN** application whitelisting is the configured signal and a binary outside every monitored
  directory is executed
- **THEN** the agent receives no permission event for it

#### Scenario: A scoped gate still decides executions inside its directories
- **WHEN** a binary inside a monitored directory is executed under application whitelisting
- **THEN** the allowlist decides it, allowing a listed binary and refusing an unlisted one

#### Scenario: A global signal keeps its reach
- **WHEN** a deny-list is configured and a deny-listed binary is executed from outside every monitored
  directory
- **THEN** it is still refused

### Requirement: A binary created after startup is still gated

Under per-file marking the agent SHALL mark executables that appear in a monitored directory after it
started, so that a newly written or moved-in binary is decided rather than silently permitted.

Without this, narrowing the mark would convert a performance improvement into a bypass: under
default-deny an unmarked binary generates no event and therefore RUNS, which is the opposite of what the
allowlist is for.

The residual race — a binary created and executed before the watcher marks it — SHALL be stated in the
operator documentation rather than implied to be absent.

#### Scenario: A binary dropped into a watched directory is refused
- **WHEN** an unlisted executable is created in a monitored directory after the agent started, and then
  executed
- **THEN** it is refused, exactly as one present at startup would have been

#### Scenario: A binary moved into a watched directory is refused
- **WHEN** an unlisted executable is moved into a monitored directory and then executed
- **THEN** it is refused
