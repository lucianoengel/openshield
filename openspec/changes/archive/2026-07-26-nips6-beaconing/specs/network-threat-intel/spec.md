## ADDED Requirements

### Requirement: Regular contact with a destination is detected without prior knowledge of it

The system SHALL detect destinations contacted at regular intervals by one subject, without requiring the
destination to appear in any feed or signature. This is the network signal that survives when the
destination is unknown, the payload is encrypted and the volume is trivial.

#### Scenario: A regular check-in is reported
- **WHEN** a subject contacts one destination at consistent intervals often enough to measure
- **THEN** a finding is reported for that destination

#### Scenario: Irregular traffic is not reported
- **WHEN** a subject's contacts with a destination are irregularly spaced
- **THEN** no finding is reported

#### Scenario: Too few contacts are not a rhythm
- **WHEN** there are too few contacts to measure regularity
- **THEN** no finding is reported, because a handful of intervals is always "regular"

### Requirement: Detection tolerates jitter and a missed check-in

Regularity SHALL be measured so that configured jitter and an occasional missed or delayed contact do not
hide a beacon. Every C2 framework offers jitter, so a detector that only catches perfect metronomes catches
only the misconfigured.

#### Scenario: A jittered beacon with one long outage is still found
- **WHEN** contacts are regular within a jitter margin and one gap is far longer than the rest
- **THEN** the finding is still reported

### Requirement: A rhythm belongs to one subject and one destination

Contacts SHALL be grouped per subject. Pooling a fleet's contacts to a shared destination would synthesize
a rhythm no endpoint exhibits — many hosts polling the same service at staggered offsets look, in
aggregate, like a metronome.

#### Scenario: A fleet's staggered polling is not a beacon
- **WHEN** many subjects each contact one destination a few times at staggered offsets
- **THEN** no finding is reported

### Requirement: Only verified telemetry contributes

Beaconing SHALL be derived only from verified events. It is inferred purely from timing, so unverified
telemetry could otherwise fabricate a beacon against any destination, or bury a real one.

#### Scenario: Unverified flows produce nothing
- **WHEN** the only matching flows are unverified
- **THEN** no finding is reported

### Requirement: A finding carries its evidence and does not enforce

A finding SHALL carry the interval, contact count and a regularity measure, and SHALL NOT trigger
enforcement. Legitimate software beacons constantly, so a finding must be dismissible at a glance and must
never act on its own.

#### Scenario: The finding is dismissible
- **WHEN** a beacon is reported
- **THEN** its interval, count and regularity are available with it

#### Scenario: Allowlisted destinations are never reported
- **WHEN** a destination is allowlisted
- **THEN** it produces no finding, while other destinations still do
