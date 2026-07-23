## MODIFIED Requirements

### Requirement: Correlated incidents are materialized with identity and state
The control plane MUST persist a correlated incident with a stable id and a lifecycle state, with at
most one open incident per subject: re-running correlation MUST update the subject's open incident
(refreshing its counts and span) rather than duplicating it, and MUST leave an acknowledged incident
unchanged so a later burst opens a new incident. An operator MUST be able to acknowledge an incident
as a unit — first-acknowledgement-wins, a non-existent incident is an error, and a database failure
during acknowledgement MUST propagate rather than read as not-found. The incident acknowledgement
surface MUST be operator-gated and mutating.

Materializing a correlated incident MUST deliver a notification when — and only when — it creates a
NEW incident. A materialization that extends the subject's existing open incident (the update path)
MUST deliver no notification, so a bursting subject pages once at incident creation, not on every
re-correlation. The notification MUST be keyed by the incident's stable id (not by a content-and-time
idempotency key), so the same incident never pages twice — including across a restart or a redundant
materialization — while a genuinely new incident for the same subject (raised after the previous one
left the open state) pages again. The notification MUST be pseudonymous (the subject, the peak risk,
and a severity summary — no content) and MUST use the same best-effort, off-ingest delivery path as
other alerts: a delivery failure MUST NOT fail materialization, and with no sink configured
materialization MUST behave exactly as before (no notification).

#### Scenario: An incident is materialized once per subject and acknowledged as a unit
- **WHEN** correlation is materialized for a bursting subject, re-materialized after another alert, and then the incident is acknowledged
- **THEN** exactly one open incident exists for the subject and is refreshed (not duplicated) on re-materialization, the acknowledgement is first-wins and moves it out of the open state, and a later burst opens a new open incident while the acknowledged one remains

#### Scenario: A new incident pages exactly once and re-materialization pages zero
- **WHEN** a subject's burst materializes a new incident and the same open incident is materialized again with a refreshed count
- **THEN** the configured sink receives exactly one notification, carrying the incident's kind, subject, and peak risk keyed by the incident id, and the re-materialization of the same open incident delivers no further notification

#### Scenario: A distinct later incident pages again
- **WHEN** a subject's incident is materialized and paged, then that incident leaves the open state, then a later burst materializes a new incident for the same subject
- **THEN** the new incident delivers its own notification rather than being suppressed as a duplicate of the first
