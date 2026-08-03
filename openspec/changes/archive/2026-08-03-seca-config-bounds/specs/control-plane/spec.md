## ADDED Requirements

### Requirement: A setting that gates detection or retention declares an operational bound

A configuration field that gates a detector or a retention window SHALL declare a bound beyond its
type's parseability, and a value outside it SHALL be refused at the moment it is set.

The entire per-field check used to be "does this parse". At single-admin tier, over the configuration
API, with no second approver and no expiry, a valid duration was enough to turn the product off: a
correlation interval long enough that no incident is ever raised, an overdue threshold long enough that
an agent someone killed is never reported missing, a retention window short enough that evidence is
purged through a SANCTIONED delete path the ledger's hash chain does not cover.

A refusal SHALL say what breaks, not only which limit was exceeded. An operator told a rule routes
around it; one told the consequence does not.

Defaults SHALL satisfy their own bounds, checked automatically — a default outside its declared range
would fail every boot.

#### Scenario: A value that disables a detector is refused
- **WHEN** a setting gating a detector or retention window is set outside its operational range
- **THEN** the change is refused, naming the setting and what the value would break

#### Scenario: An ordinary setting is still accepted
- **WHEN** a value within the operational range is set
- **THEN** it is accepted — a bound that refuses reasonable settings is a bound that gets removed

### Requirement: Whether a configuration change reduces detection is computable, not a judgement

Each configuration field SHALL declare which DIRECTION of change reduces what the deployment can detect
or retain, and a change SHALL be evaluated against that declaration.

A bound cannot cover this. Most of these changes use values that are perfectly reasonable in isolation —
a 24-hour retention is a legitimate choice and a suspicious one on the day an incident is opened — so no
range refuses them. What was missing is the direction, and whether a change reduced the deployment's
ability to see is not a matter of opinion.

A value that DISABLES its feature SHALL order as the weakest setting, not by its magnitude. An interval
of zero that disables scheduled correlation is not the most frequent possible sweep; ordered
numerically, the single change that stops incidents being raised at all would score as a hardening.

An unordered value — an allowlist, a routing table — SHALL treat ANY change as reducing detection, since
no comparison of two strings distinguishes an added command-and-control destination from an added CDN.

The declaration SHALL be enforced by a test naming every field that carries one, so a newly added
detection setting cannot be left unclassified — an undeclared direction reads as "irrelevant to
detection", which is the safe-looking default and the wrong one.

#### Scenario: Widening a detection window registers as weakening
- **WHEN** a threshold, interval or retention window is changed in the direction that detects or retains
  less
- **THEN** the change is recorded as reducing detection

#### Scenario: Disabling a detector is not recorded as a hardening
- **WHEN** an interval whose zero value disables its feature is set to zero
- **THEN** the change is recorded as reducing detection

### Requirement: A configuration change that reduces detection raises an alert and is recorded as such

A change that reduces detection SHALL raise an alert on the notification channel, naming the settings
and the author, and SHALL be recorded on the revision diff.

A log entry is not sufficient. The threat is an operator credential being used to blind the product
before the thing it would have caught, and nobody reads a configuration history at the moment that
matters. The recorded flag is the other half: an investigator reconstructing "what changed before we
stopped seeing anything" must find the judgement made at the time, per change, rather than re-derive it
per key.

The judgement SHALL be recorded when the change is made rather than derived when the history is read, so
that later edits to the field declarations cannot reinterpret past changes.

A change that INCREASES detection SHALL NOT alert. An alert on every configuration change is one that
gets muted, and the weakening change is then muted with it.

#### Scenario: Widening the dead-man's-switch pages someone
- **WHEN** the silence tolerated before an agent is reported missing is increased
- **THEN** an alert names the setting and the author, and the revision diff records the change as
  reducing detection

#### Scenario: A tightening change is silent
- **WHEN** the same setting is decreased, or a retention window lengthened
- **THEN** no weakening alert is raised

#### Scenario: A mixed revision is judged per change
- **WHEN** one revision both tightens one setting and loosens another
- **THEN** each change carries its own judgement
