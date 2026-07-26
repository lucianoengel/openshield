## ADDED Requirements

### Requirement: An incident's timeline lists its contributing alerts, time-ordered across domains

The system SHALL return, for a cross-domain incident, every alert recorded as contributing to it, ordered
by DETECTION time across all domains — so an operator reads one interleaved narrative rather than a
per-domain list. Each entry SHALL carry the alert's domain, severity, subject, title and detection time.

Ordering SHALL be by detection time, not by alert id. Alert ids are insertion order, which is the order
the control plane happened to receive alerts; using them would misrepresent the cross-domain interleaving
that is the entire point of the timeline.

#### Scenario: A cross-domain incident's timeline is complete and interleaved
- **WHEN** an incident correlated from alerts in three domains is requested
- **THEN** the timeline contains every contributing alert, ordered by detection time, with domains
  interleaved as they occurred
- **AND** the test FAILS if the contributing-alert join is not written, or if entries are ordered by
  alert id instead of detection time

#### Scenario: An incident kind with no alert join says so
- **WHEN** the timeline of a single-domain burst incident is requested
- **THEN** the response explicitly states that this incident kind has no timeline
- **AND** it is NOT an empty list, which would read as "nothing contributed"

### Requirement: Each entry carries an evidence reference with an explicit resolution state

A timeline entry SHALL carry the reference to what produced its alert (the originating event id and
decision id) and a resolution state:

- **resolved** — the referenced decision was found in the audit ledger, and the entry reports that
  entry's coordinates (its sequence number and hash).
- **unresolved** — the reference exists but the ledger entry is not reachable from the control plane's
  database. The reference SHALL be returned intact, and the entry SHALL NOT be omitted.
- **derived** — the alert is a server-side derivation (peer-UEBA) with no originating endpoint event or
  decision at all. The entry SHALL say so rather than presenting empty reference fields.

The per-agent forward-secure ledger is a different trust domain from the fleet aggregate (D30).
Resolution SHALL NOT be satisfied by returning an aggregate telemetry row in place of a ledger entry:
the aggregate is not evidence, and presenting it as one would make the timeline's strongest-looking claim
its most misleading.

#### Scenario: A decision-projected alert resolves to ledger coordinates
- **WHEN** a timeline entry's alert came from a decision whose ledger entry exists in the reachable
  database
- **THEN** the entry is marked resolved and reports that ledger entry's sequence and hash

#### Scenario: An unreachable ledger entry is marked, not hidden
- **WHEN** a timeline entry's alert references a decision with no reachable ledger row
- **THEN** the entry is marked unresolved, still lists the alert, and still carries the reference
- **AND** the test FAILS if the implementation substitutes the aggregate telemetry row as the resolved
  ledger entry

#### Scenario: A server-derived alert is labelled as such
- **WHEN** a timeline includes a server-side peer-UEBA alert
- **THEN** that entry is marked as a server derivation with no originating event, rather than showing
  blank reference fields

### Requirement: The timeline reports ledger coordinates and does not claim verification

A resolved entry's reported sequence and hash SHALL be presented as the coordinates of the referenced
entry, NOT as a verification result. The system SHALL NOT re-walk or re-verify the hash chain here, and
the response SHALL NOT describe a resolved entry as verified, intact, or proven.

Equally, an unresolved entry SHALL NOT be described as tampered or missing evidence — the ordinary cause
is that the agent's ledger is not in the database the control plane reads.

#### Scenario: Resolution is reachability, not integrity
- **WHEN** a timeline entry resolves to a ledger entry
- **THEN** the response reports the entry's coordinates and makes no claim that the chain was verified

### Requirement: Reading a timeline is recorded

Serving an incident timeline SHALL write an investigation-view record naming the viewer, so obtaining an
incident's evidence references always leaves a trace. A request without an identified viewer SHALL be
refused. An unknown incident id SHALL be a not-found response, not an empty timeline.

#### Scenario: A served timeline is recorded
- **WHEN** an operator requests an incident's timeline
- **THEN** an investigation-view row naming that operator exists afterwards
- **AND** the test FAILS if the view recording is removed

#### Scenario: An unknown incident is not-found
- **WHEN** a timeline is requested for an id that does not exist
- **THEN** the response is not-found rather than an empty timeline
