## ADDED Requirements

### Requirement: The ATT&CK technique vocabulary is closed and derivable-only

The set of technique ids the system may emit SHALL be a single closed vocabulary, and every id the
signal mapper can produce SHALL be a member of it. The system SHALL expose that membership check so a
consumer can refuse an id from outside the vocabulary.

An id in the vocabulary that no signal shape can produce SHALL be reported as a defect: it would be
accepted in an operator's hunt and could never match.

Sub-technique ids SHALL NOT be rolled up to their parents. When the mapper derives `T1567.002`, the
system SHALL NOT also emit `T1567` — the parent is a broader claim than the evidence supports.

#### Scenario: Every derivable technique is a vocabulary member
- **WHEN** every signal shape the mapper branches on is evaluated
- **THEN** each technique id produced is a member of the vocabulary, and each has a display name

#### Scenario: An id outside the vocabulary is not recognized
- **WHEN** the membership check is asked about an invented id, a real ATT&CK id this build cannot
  derive, a differently-cased id, or the parent of a derived sub-technique
- **THEN** it reports the id as unknown

### Requirement: A technique id is stable; its name is looked up per build

A technique's ID SHALL be the value that crosses a contract boundary or is persisted. The display NAME
SHALL be resolved at presentation time from the running build's table, and SHALL NOT be persisted
alongside the id.

MITRE renames techniques, and a name written into a hash-chained ledger is frozen at the moment of
writing and cannot be corrected without breaking the chain.

#### Scenario: A name is resolved, not stored
- **WHEN** a technique id is carried on a decision or an alert
- **THEN** only the id is stored, and the display name is obtained by looking the id up
