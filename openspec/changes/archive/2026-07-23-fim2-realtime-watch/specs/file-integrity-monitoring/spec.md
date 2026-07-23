## ADDED Requirements

### Requirement: File-integrity drift is detected in real time

The system SHALL detect a change to a watched critical file in real time, without waiting for the
periodic scan, by watching the critical paths for change events and triggering an immediate baseline
re-check when one occurs. The change event MUST only trigger the re-check; the drift itself MUST still be
computed by the cryptographic baseline scan, so a modification is confirmed by a content-hash difference
(a timestomped edit is caught, a change that does not alter content yields no drift). The real-time watch
SHALL be additive to the periodic scan, which remains the completeness backstop, and SHALL be
best-effort: if the watch cannot be established, the system MUST log and continue with the periodic scan
rather than fail.

#### Scenario: A modified critical file is detected without waiting for the poll
- **WHEN** a watched critical file's content is changed
- **THEN** a drift event is produced well within the periodic scan interval, triggered by the change

#### Scenario: A benign change that does not alter content produces no drift
- **WHEN** a watched file receives a change event but its content (hash) is unchanged
- **THEN** no drift is produced (the baseline scan confirms it, not the raw event)

#### Scenario: An unavailable watch degrades to the periodic scan
- **WHEN** the real-time watch cannot be established
- **THEN** the condition is logged and file-integrity monitoring continues via the periodic scan
