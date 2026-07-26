## ADDED Requirements

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

### Requirement: A cross-domain incident materializes once and pages once

A cross-domain incident SHALL be persisted as an upsert on its entity, so a re-run of the rule extends
the entity's open incident rather than duplicating it. A human SHALL be paged only when the upsert
genuinely INSERTED a new incident — a re-correlation that updates the open incident SHALL NOT re-page.

A cross-domain incident and a single-domain burst incident for the same asset SHALL be able to coexist:
they are distinguished by kind, and neither SHALL displace the other through the uniqueness constraint.

#### Scenario: Re-running the rule does not re-page
- **WHEN** the cross-domain rule is materialized twice over the same alerts
- **THEN** one incident exists and exactly one page was emitted
- **AND** the test FAILS if the insert-vs-update detection is dropped

#### Scenario: Both incident kinds coexist for one asset
- **WHEN** an asset has an open burst incident and then a cross-domain incident is materialized for it
- **THEN** both rows exist, each with its own kind, and neither upsert overwrites the other
