## ADDED Requirements

### Requirement: An exclusion is configurable, and refused when unusable

The exclusion set SHALL be configurable on the agent — path prefixes and daily local-time windows —
and SHALL be validated when it is read. A malformed window, an empty window whose start equals its
end, or a window that crosses midnight SHALL be refused, naming the offending window, and the
component SHALL NOT start with a partial exclusion set.

A predicate with no way to configure it is not a control. A silently-dropped window is worse than
none: the operator wrote a break into the configuration, told a works council about it, and the agent
observed straight through it with nothing anywhere saying so.

A window crossing midnight is refused rather than split, because the interval is a half-open
[start, end) comparison on minutes since midnight and a crossing window matches nothing — the same
silent failure in a different shape.

#### Scenario: A malformed window refuses the configuration
- **WHEN** an exclusion window is not `HH:MM-HH:MM`, is out of range, has equal start and end, or
  crosses midnight
- **THEN** it is refused with the offending window named, and no exclusions are installed

#### Scenario: A configured window excludes exactly its interval
- **WHEN** a `12:00-13:00` window is configured
- **THEN** 12:00 and 12:59 are excluded and 11:59 and 13:00 are not

### Requirement: An exclusion window is evaluated in local time

An exclusion window SHALL be evaluated against the event's LOCAL time.

The window is expressed as a wall-clock interval an operator agreed with a works council. Evaluating
it against UTC would still exclude an hour a day — the wrong hour — and nothing about the running
system would look broken.

#### Scenario: A break window applies at the operator's clock
- **WHEN** an event is observed at 12:30 local time under a 12:00-13:00 window
- **THEN** it is excluded, whatever the host's offset from UTC

### Requirement: An exclusion never suppresses an enforcement verdict

An exclusion SHALL apply to the observation path only. A producer that asks the pipeline for a verdict
it will act on — an execution gate, a clipboard mediator, a print or mail decider — SHALL receive a
decision regardless of any configured exclusion.

A suppressed verdict necessarily resolves to allow, so an exclusion applied there would turn a
break-time window into a nightly interval in which anything runs, reachable by any user willing to
wait for it. The exclusion set is a privacy control, not a user-invokable evasion, and suppressing a
verdict is that evasion.

#### Scenario: A verdict is decided for an excluded subject
- **WHEN** a verdict is requested for a subject matching both a path exclusion and a time window
- **THEN** a decision is produced and classification runs, and no exclusion is counted

### Requirement: An unevaluable exclusion is counted rather than guessed

The system SHALL count and report every file event that a configured path exclusion could not be
evaluated against because the subject identity carries no resolvable path, and SHALL observe such an
event. It SHALL NOT be silently excluded, and SHALL NOT be silently observed.

An event that is not about a file SHALL NOT be counted: a personal-folder exclusion was never
applicable to it, and counting it would report a hole far larger than the one that exists.

The count is the size of the gap in the claim "these folders are not observed". A privacy control with
an unmeasured blind spot is a false statement to the people it was agreed with.

#### Scenario: A path-less file event is counted
- **WHEN** a path exclusion is configured and a file event carries a subject identity with no path
- **THEN** the event is not excluded, and the unevaluable count increases

#### Scenario: A non-file event is not counted as a gap
- **WHEN** a path exclusion is configured and a network event is observed
- **THEN** the unevaluable count does not increase

#### Scenario: A time window is never unevaluable
- **WHEN** a time window is configured and a file event carrying no path is observed inside it
- **THEN** it is excluded and the unevaluable count does not increase
