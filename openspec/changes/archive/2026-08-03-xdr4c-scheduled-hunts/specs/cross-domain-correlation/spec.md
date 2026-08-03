## ADDED Requirements

### Requirement: Ordered-sequence rules run on the correlation clock

The scheduled correlation loop SHALL materialize configured ordered-sequence rules ("hunts") on the
same tick as the breadth rule, so a domain or ATT&CK sequence raises an incident and pages a human
without an operator request.

Before this, the sequence fields were set in exactly one place outside tests — the incidents query
parser — so the platform could answer "did this chain happen?" for an operator who already suspected
it, and could never report one.

The breadth rule SHALL continue to run alongside the hunts. A sequence rule is strictly narrower than
the breadth rule it derives from, so hunts SHALL be additive and SHALL NOT suppress a breadth incident.

A hunt whose materialization fails SHALL be counted and named, and the remaining hunts SHALL still run.

#### Scenario: A narrative incident is raised with nobody asking
- **GIVEN** two assets that both satisfy the breadth rule, only one of which evidences the configured
  technique sequence
- **WHEN** the scheduled loop runs with that hunt configured and no request is made
- **THEN** the evidencing asset raises an incident named for the hunt and a page is emitted
- **AND** the other asset raises the breadth incident and no hunt incident

#### Scenario: A hunt pages once across many ticks
- **WHEN** the loop re-materializes the same hunt on tick after tick
- **THEN** exactly one page was emitted for it

### Requirement: A cross-domain incident is identified by its rule as well as its entity

A cross-domain incident SHALL be keyed by the correlating rule's name in addition to the entity, and
the open-incident uniqueness constraints SHALL include it. The unnamed rule is the breadth rule.

Without this, two hunts matching one entity share a kind and therefore share the conflict target: the
second upsert takes the update path, overwrites the first hunt's counts with its own, and — because
only a genuine insert pages — never pages at all. A second attack narrative on the same asset would be
folded silently into the first one's incident, and the row would flip-flop on every tick.

#### Scenario: Two hunts on one asset raise two incidents and page twice
- **GIVEN** one asset evidencing two distinct configured narratives
- **WHEN** both hunts are materialized
- **THEN** two open incidents exist, one per hunt name, and two pages were emitted

#### Scenario: Re-running both hunts converges
- **WHEN** the same two hunts are materialized again
- **THEN** the two incidents are extended rather than duplicated, and no further page is emitted

#### Scenario: The breadth rule coexists with a hunt
- **WHEN** the breadth rule and a hunt both match one asset
- **THEN** both incidents exist, the breadth one carrying the unnamed rule

### Requirement: A hunt that could never match is refused at load

A hunt configuration SHALL be validated when it is read, and a hunt SHALL be refused when it names a
domain no producer emits, names a technique this build cannot derive, has no name, shares a name with
another hunt, constrains no sequence at all, names a severity that is not a bucket, or carries an
unrecognized field. Every refusal SHALL name the offending hunt and value.

A rule that matches nothing is indistinguishable from an all-clear, and a mistyped hunt sits in the
deployed file producing that silence for as long as it is configured. An unrecognized field is refused
rather than ignored because a misspelled threshold would otherwise load a rule that runs over defaults
the file does not state.

A configuration that fails to load SHALL leave hunts inactive and say so, and SHALL NOT substitute a
default — raising incidents against a narrative nobody wrote is worse than raising none.

#### Scenario: An underivable technique is refused
- **WHEN** a hunt names a real ATT&CK technique this build cannot derive
- **THEN** the load fails, naming the hunt and the technique

#### Scenario: A duplicate hunt name is refused
- **WHEN** two hunts share a name
- **THEN** the load fails, because the second would merge into the first's incident and never page

#### Scenario: A hunt that constrains nothing is refused
- **WHEN** a hunt declares neither a domain nor a technique sequence
- **THEN** the load fails, because it is the breadth rule under another name and would double its
  incidents

#### Scenario: A misspelled threshold is refused
- **WHEN** an otherwise valid hunt carries an unrecognized field name
- **THEN** the load fails naming the field, rather than silently running over the default threshold

### Requirement: A page names the hunt that raised the incident

A notification for a hunt incident SHALL name the hunt. A notification for the breadth rule SHALL NOT
invent one.

Two hunts on one asset produce identical breadth text, and which narrative matched is the only claim a
sequence rule makes that the breadth rule does not. The hunt name is operator-authored free text and
SHALL therefore reach the notification only — never a derived table's title or dedup key.

#### Scenario: The hunt is named in the page
- **WHEN** a configured hunt raises an incident
- **THEN** the delivered notification carries the hunt's name

## MODIFIED Requirements

### Requirement: A cross-domain incident materializes once and pages once

A cross-domain incident SHALL be persisted as an upsert on its entity AND the correlating rule's name,
so a re-run of the same rule extends that rule's open incident for the entity rather than duplicating
it. A human SHALL be paged only when the upsert genuinely INSERTED a new incident — a re-correlation
that updates the open incident SHALL NOT re-page.

A cross-domain incident and a single-domain burst incident for the same asset SHALL be able to coexist:
they are distinguished by kind, and neither SHALL displace the other through the uniqueness constraint.

Two cross-domain incidents raised by DIFFERENT rules for the same asset SHALL likewise coexist: they
are distinguished by rule name, and neither SHALL displace the other.

#### Scenario: Re-running the rule does not re-page
- **WHEN** the cross-domain rule is materialized twice over the same alerts
- **THEN** one incident exists and exactly one page was emitted
- **AND** the test FAILS if the insert-vs-update detection is dropped

#### Scenario: Both incident kinds coexist for one asset
- **WHEN** an asset has an open burst incident and then a cross-domain incident is materialized for it
- **THEN** both rows exist, each with its own kind, and neither upsert overwrites the other

#### Scenario: Two rules' incidents coexist for one asset
- **WHEN** two differently-named cross-domain rules both match one asset
- **THEN** both rows exist, each with its own rule name, and neither upsert overwrites the other
