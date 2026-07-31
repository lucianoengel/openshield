# notification-routing Specification

## Purpose
An ordered kind/severity → named-sink routing table over the existing multi-sink fanout (SOAR-9), with
first-match-wins so exclusivity is expressible, and a counted fail-open so a table with a hole
over-notifies visibly rather than going silent. Routing decides on a closed vocabulary and never on a
subject.

## Requirements

### Requirement: Notifications are routed to named sinks by kind and severity

The system SHALL support an ordered table of routing rules, each matching a notification's kind and a
minimum severity and selecting one or more NAMED sinks. The FIRST matching rule SHALL decide, and later
rules SHALL NOT also apply. First-match-wins is what makes "critical goes to the pager and nowhere else"
expressible; a union of every matching rule cannot express exclusivity, so the highest-severity page
would always also go everywhere a broader rule pointed.

#### Scenario: Critical routes to the pager only
- **WHEN** a critical notification matches a rule selecting the pager sink
- **THEN** the pager sink receives it and no other sink does

#### Scenario: Informational routes to the chat sink only
- **WHEN** a low-severity notification falls to a later rule selecting the chat sink
- **THEN** the chat sink receives it and the pager does not

#### Scenario: A rule constrained by kind does not match another kind
- **WHEN** a rule names specific notification kinds
- **THEN** a notification of a different kind does not match it

### Requirement: An unroutable notification is delivered everywhere and counted

A notification matching no rule SHALL be delivered to EVERY configured sink, and the occurrence SHALL be
counted and exposed. Silently dropping an alert because a routing table was misconfigured is the worst
available outcome — the alert that fits no rule is disproportionately likely to be the novel one.
Over-notifying is recoverable; the counter makes the misconfiguration visible rather than leaving an
operator to infer it from silence.

#### Scenario: No rule matches
- **WHEN** a notification matches no routing rule
- **THEN** every sink receives it and the unrouted counter increases

#### Scenario: A sink named by a rule but not configured does not swallow the notification
- **WHEN** a matching rule names a sink that does not exist
- **THEN** the notification is still delivered to the sinks that do exist, and the rule's error is visible

### Requirement: A routing table is validated when it is loaded

A routing table SHALL be validated at load: an unknown severity, an unknown notification kind, a rule with
no sinks, or a rule naming an unconfigured sink SHALL be refused. A routing mistake discovered at
delivery time is discovered by an alert not arriving.

#### Scenario: An unknown severity is refused at load
- **WHEN** a rule names a severity outside the closed vocabulary
- **THEN** loading fails and names the offending value

#### Scenario: A rule naming no sink is refused
- **WHEN** a rule selects no sinks
- **THEN** loading fails, rather than creating a rule that silently discards everything matching it

### Requirement: Routing decisions use kind and severity only

Routing SHALL match on notification kind and severity and SHALL NOT match on subject, entity or any other
identifier. A routing table that selects on a subject puts a pseudonymous identity into a rule an operator
reads and edits, which is both a re-identification surface and a way to route one person's alerts away
from view.

#### Scenario: No rule field selects a subject
- **WHEN** a routing rule is loaded
- **THEN** it exposes no subject, entity or agent selector

### Requirement: Delivery still reaches every selected sink independently

Routing SHALL preserve the existing fanout guarantee: one failing sink SHALL NOT suppress delivery to the
others, and failures SHALL be aggregated rather than short-circuited.

#### Scenario: One selected sink fails
- **WHEN** a rule selects two sinks and one returns an error
- **THEN** the other still receives the notification and the error is reported

### Requirement: An unacknowledged incident escalates on a timer

The control plane SHALL support an ordered ESCALATION LADDER: rungs of the form "after this long
unacknowledged, notify these sinks", fired against incidents that are still open. Escalation SHALL be a
distinct notification kind, routable like any other, rather than a re-send of the original — routing keys
on kind, so a re-send arrives exactly where the page nobody answered went.

This closes the half of alerting that routing did not. Routing decided WHERE a notification goes at the
moment it is raised; nothing decided what happens when it goes there and no one answers. The page is
delivered, delivery is recorded as a success, and the incident sits open — every part of the machine
reporting that it worked.

Acknowledging an incident SHALL stop its ladder, and that SHALL be a consequence of the incident leaving
the open state rather than a separate cancellation step.

Each rung SHALL fire AT MOST ONCE per incident, durably, so that a restart, a leader handover or a
repeated sweep does not re-fire it. The claim SHALL be recorded BEFORE the notification is sent: sending
first would re-page on any crash in between, and the crash window is when an operator can least absorb a
duplicate. Each rung's notification SHALL carry its own idempotency key, or a receiver deduping on the key
treats a later rung as a retry of an earlier one and discards it.

A rung's deadline SHALL be measured from when the incident was raised, so the ladder that executes is the
one the operator wrote rather than one that depends on when a sweep happened to run.

A ladder SHALL be validated when it is loaded: a rung with no sinks, no deadline, an unknown sink, an
unknown severity, a deadline not after the previous rung's, or an unrecognised field SHALL be refused. An
out-of-order ladder SHALL be refused rather than silently sorted — sorting delivers a working ladder that
is not the one that was written, which is the failure nobody then finds.

This is a TIMER and SHALL NOT claim to be a schedule. There is no rotation, calendar or on-call roster;
those require a roster this product does not have, and a half-built rotation that pages the wrong person
is worse than none. The roster half stays named as absent.

Rungs fired and sweeps that failed SHALL both be counted and exposed. A ladder that has stopped climbing
is externally indistinguishable from a fleet where everything is acknowledged promptly, and that is the
flattering reading.

#### Scenario: An ignored incident escalates and an acknowledged one does not
- **WHEN** the sweep runs against one unacknowledged and one acknowledged incident, both past a deadline
- **THEN** only the unacknowledged one escalates
- **AND** the escalation is delivered as the escalation kind, naming the incident

#### Scenario: A rung fires once however often the sweep runs
- **WHEN** the sweep runs repeatedly against the same still-open incident
- **THEN** the rung is delivered exactly once

#### Scenario: The ladder climbs by its own deadlines
- **WHEN** an incident is older than the first two rungs' deadlines but not the third's
- **THEN** exactly the first two fire, each under its own idempotency key

#### Scenario: A severity floor and a deadline are both honoured
- **WHEN** a rung names a minimum severity, or an incident is younger than a rung's deadline
- **THEN** that rung does not fire for it

#### Scenario: A structurally bad ladder is refused at load
- **WHEN** a ladder has a rung with no sinks, no deadline, an unknown sink or severity, a deadline out of
  order, or an unrecognised field
- **THEN** loading it fails rather than producing a ladder that runs and does the wrong thing
