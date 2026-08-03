

## Purpose

Correlation across detection domains: alerts are grouped by GRAPH ENTITY rather than by subject string,
so a device seen as a hostname in one domain and a user in another correlate as one thing. A window rule
raises at most one incident per entity, a sequence rule matches an ORDERED subsequence, severity
escalates with the breadth of domains involved, and materialization is idempotent and records which
alerts contributed.

## Requirements

### Requirement: Materialization records which alerts contributed, idempotently

When a cross-domain incident is materialized, the system SHALL record the set of alerts that contributed
to it, and SHALL store the incident's distinct domain list. Re-materializing the same correlation SHALL
NOT duplicate the contribution records — a re-run extends the incident, so its evidence set must converge
rather than grow.

An alert may contribute to a later re-materialization of the same open incident; the record SHALL
accumulate the union, never a duplicate row for the same (incident, alert) pair.

#### Scenario: The contributing set is recorded
- **WHEN** a cross-domain incident is materialized from four alerts across three domains
- **THEN** exactly four contribution records exist for that incident, and the incident's domain list has
  three entries

#### Scenario: Re-materialization does not duplicate contributions
- **WHEN** the same correlation is materialized twice
- **THEN** the contribution record count is unchanged after the second run
- **AND** the test FAILS if the conflict-ignoring insert is dropped

### Requirement: Alerts correlate by graph entity, never by subject string

Cross-domain correlation SHALL group alerts by the XDR graph `entity_id` recorded on each unified alert,
and SHALL NOT group by the alert's subject string. One asset is often named differently by different
domains — the endpoint knows a device pseudonym, the access proxy knows a user identity, and the graph
links them — so grouping by subject would split a single asset into several and the multi-domain
condition would never be met for exactly the attacks this rule exists to catch.

#### Scenario: A device⋈user asset correlates as one entity
- **WHEN** alerts from different domains are recorded for a device subject and for a user subject that
  the entity graph has linked into one entity
- **THEN** they group into ONE cross-domain incident for that entity
- **AND** the test FAILS if the correlation groups by subject string instead of the entity join

#### Scenario: Alerts on different entities do not correlate
- **WHEN** the same set of domains' alerts is spread across DIFFERENT entities, one domain each
- **THEN** no cross-domain incident is raised for any of them

<!-- restored from 2026-07-26-xdr4-cross-domain-correlation -->

### Requirement: A multi-domain window rule raises one incident per entity

The system SHALL raise a cross-domain incident for an entity whose alerts inside the look-back window
span at least a configured minimum number of DISTINCT domains. The incident SHALL carry the entity id,
the alert count, the distinct-domain count, and the first/last alert times. An entity below the domain
threshold, or whose alerts fall outside the window, SHALL NOT raise one.

Only alerts inside the window are considered; the rule SHALL NOT retro-correlate alerts that predate it.

#### Scenario: Three domains on one entity raise one incident
- **WHEN** an endpoint exec alert, a network DNS alert and a UEBA anomaly alert are recorded for one
  entity inside the window, with a minimum of three domains required
- **THEN** exactly ONE cross-domain incident exists for that entity with a domain count of three
- **AND** it is sourced from the unified alert stream, not from the single-domain UEBA alert table

#### Scenario: A single-domain entity raises nothing
- **WHEN** an entity has many alerts inside the window but all from ONE domain, with a minimum of two
  domains required
- **THEN** no cross-domain incident is raised for it
- **AND** the test FAILS if the minimum-domains condition is dropped from the query

<!-- restored from 2026-07-26-xdr4-cross-domain-correlation -->

### Requirement: The sequence rule matches an ORDERED subsequence

When an operator supplies a domain sequence, the system SHALL raise the incident only when the entity's
alerts, ordered by detection time, contain that sequence as an ordered SUBSEQUENCE (other domains may
appear between the steps). An entity whose alerts contain the same domains in a DIFFERENT order, or that
is missing a step, SHALL NOT match.

Set containment is not sufficient and SHALL NOT be used: "these three domains all fired" is a materially
weaker claim than "they fired in this order", and an attack narrative is an ordering claim.

#### Scenario: The right domains in the wrong order do not match
- **WHEN** a sequence of three domains is required and an entity's alerts contain exactly those domains
  in reverse order
- **THEN** no cross-domain incident is raised for that entity
- **AND** the test FAILS if the check is relaxed to set containment

#### Scenario: Interleaved alerts still match
- **WHEN** an entity's ordered alerts contain the required sequence with unrelated domains interleaved
  between the steps
- **THEN** the incident is raised

<!-- restored from 2026-07-26-xdr4-cross-domain-correlation -->

### Requirement: Severity escalates with domain breadth, in the existing vocabulary

A cross-domain incident's severity SHALL start from the highest severity among its contributing alerts
and rise ONE bucket for each distinct domain beyond the first, capped at the top bucket. It SHALL use the
existing four-bucket severity vocabulary and SHALL NOT introduce a second scale.

The escalation is a triage-ordering heuristic. It SHALL NOT be presented as evidence, and a correlated
incident SHALL NOT be described as a confirmed true positive — correlation raises confidence, it does not
establish certainty (D4).

#### Scenario: Breadth raises the bucket
- **WHEN** an entity's contributing alerts are all `low` severity but span three domains
- **THEN** the incident's severity is two buckets above `low`

#### Scenario: The cap holds
- **WHEN** an entity's alerts are already at the top bucket and span four domains
- **THEN** the incident's severity is the top bucket, not an out-of-vocabulary value

<!-- restored from 2026-07-26-xdr4-cross-domain-correlation -->

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

<!-- restored from 2026-07-26-xdr4-cross-domain-correlation -->

### Requirement: A decision carries the ATT&CK techniques its evidence supported

A Decision SHALL carry the MITRE ATT&CK technique ids derived from the signals the decision was made
over. Those ids SHALL come from the platform's own signal derivation — the same derivation supplied to
policy as input — and SHALL NOT be read out of the policy result.

A policy module is operator-authored text. If a rule could declare a technique, then "what did this
asset evidence?" would be answered by whatever the rules asserted, and technique-level correlation
would correlate claims rather than signals.

An empty technique list is a real answer ("no signal mapped to a technique"), not a missing one.

#### Scenario: The derivation reaches the decision
- **WHEN** a credential is written to a cloud-sync path and the policy decides
- **THEN** the decision carries exactly the technique ids the signals evidence, and satisfies the
  decision contract

#### Scenario: A policy cannot declare a technique
- **WHEN** a policy module returns a result containing technique ids, over an event whose signals map
  to no technique
- **THEN** the decision carries no techniques

### Requirement: The decision contract refuses a technique outside the vocabulary

The decision contract SHALL reject a decision carrying any technique id that is not a member of the
closed vocabulary, and a rejected decision SHALL NOT be projected into the alert stream at all — not
projected with the offending field stripped.

Signature verification establishes who sent a decision, not that what they sent is expressible in the
platform's contract. These ids are what operators hunt over, so an enrolled-but-compromised producer
that could write arbitrary ids could manufacture an attack chain no signal evidenced.

#### Scenario: A forged technique does not reach the alert stream
- **WHEN** a verified producer publishes a decision carrying a technique id this build cannot derive
- **THEN** a contract violation is counted, no alert is written for that decision, and no alert in the
  stream carries the forged id

#### Scenario: A well-formed decision's techniques are persisted
- **WHEN** a decision carrying vocabulary-member technique ids is projected
- **THEN** the resulting unified alert carries exactly those ids

### Requirement: A correlation rule may name an ordered technique sequence

The cross-domain rule SHALL accept an optional ordered sequence of ATT&CK technique ids that an
entity's alerts must contain as an ordered subsequence, composing with — not replacing — the domain
sequence. Both constraints SHALL hold when both are given.

Two steps of a technique sequence SHALL NOT be satisfied by the same alert. An alert may carry several
techniques, but a sequence is an ordering claim and one alert is one moment: it cannot evidence "then".

An alert carrying no technique SHALL NOT satisfy any step.

Each correlated incident SHALL report the distinct techniques its contributing alerts carried, in
first-seen order.

#### Scenario: The chain matches and its permutations do not
- **GIVEN** three entities that all satisfy the plain cross-domain rule, one evidencing T1552 then
  T1567.002 on separate alerts, one the reverse order, and one carrying both on a single alert
- **WHEN** the rule is run with the technique sequence T1552 then T1567.002
- **THEN** only the first entity raises an incident, and that incident reports both techniques

#### Scenario: An entity with no techniques is not swept in
- **GIVEN** an entity whose alerts carry no techniques and which correlates under the plain rule
- **WHEN** any technique sequence is requested
- **THEN** that entity raises no incident

### Requirement: A technique sequence naming an underivable id is refused

A correlation request whose technique sequence names an id outside the vocabulary SHALL be rejected
with a client error naming the offending id, never silently accepted.

A step no producer can emit would never match, and the operator would read the resulting empty list as
"that attack chain did not happen".

#### Scenario: An unknown technique is a 400
- **WHEN** an operator requests a technique sequence containing an invented id, a real ATT&CK id this
  build cannot derive, the parent of a derived sub-technique, or a differently-cased id
- **THEN** the request is rejected with a client error quoting the id

#### Scenario: A well-formed technique sequence is served
- **WHEN** an operator requests a valid technique sequence over the correlation endpoint
- **THEN** the response lists the matching incidents, each carrying its techniques

### Requirement: Replay compares a decision's techniques

Decision replay SHALL compare the technique list, including its order, and report a difference as a
divergence.

The techniques are a deterministic derivation of the same signals the policy saw, so a replay that
reproduces the action but not the techniques is a real divergence. Excluding them would leave the
field operators hunt over unable to be proven derived rather than asserted.

#### Scenario: A technique difference is a divergence
- **WHEN** two decisions agree on every other compared field but differ in the presence, absence,
  identity or order of a technique
- **THEN** replay reports a divergence

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
