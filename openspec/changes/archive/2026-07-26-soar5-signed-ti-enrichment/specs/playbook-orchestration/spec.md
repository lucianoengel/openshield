## ADDED Requirements

### Requirement: Enrichment performs a threat-intel lookup against the IOC store

The `enrich` step SHALL resolve each contributing alert's evidence to the originating event, extract the
network observables that event already carries, match them against the IOC store, and record a `ti`
annotation naming the matched indicator and the feed that asserted it. An incident with no match SHALL
receive no `ti` annotation — an annotation that says "nothing found" trains an analyst to skip them.

#### Scenario: A known-bad destination is annotated
- **WHEN** an incident's alert has evidence naming a destination that matches an indicator
- **THEN** a `ti` annotation records the matched indicator and its feed

#### Scenario: A clean incident gets no threat-intel annotation
- **WHEN** no observable matches any indicator
- **THEN** no `ti` annotation is written

### Requirement: Only verified evidence may steer enrichment

Enrichment SHALL read observables only from events recorded as VERIFIED (D44). Unverified telemetry is
not evidence, and allowing it to decide that an incident is threat-intel-confirmed would let anyone able
to publish unsigned telemetry manufacture confidence in — or distract from — an incident.

#### Scenario: An unverified event carrying a known-bad destination is ignored
- **WHEN** the only event naming a matching destination is not verified
- **THEN** no `ti` annotation is written

### Requirement: A threat-intel hit is context, never enforcement

A threat-intel match SHALL annotate only. It MUST NOT raise an alert, change an incident's severity,
advance its lifecycle, or actuate. Turning public threat intelligence into automatic enforcement is how a
poisoned or over-broad feed becomes a denial of service.

#### Scenario: A match changes nothing but the annotation
- **WHEN** enrichment records a threat-intel match
- **THEN** the incident's severity, state and alert set are unchanged
