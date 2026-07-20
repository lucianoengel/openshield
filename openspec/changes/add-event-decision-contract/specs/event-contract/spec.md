## ADDED Requirements

### Requirement: Event identity and provenance
Every `Event` SHALL carry a producer-assigned unique ID, a monotonic sequence number scoped to
the producing agent, an emission timestamp, and the identifier of the connector that produced
it. Sequence numbers exist so that suppression of events is detectable, not only modification —
an audit trail that cannot reveal gaps is not evidentiary.

#### Scenario: Event carries provenance
- **WHEN** a connector emits an Event
- **THEN** the Event has a non-empty `event_id`, `agent_id`, `connector_id`, `sequence` and
  `observed_at`
- **AND** rejecting an Event missing any of these is enforced by a validation test, not by
  reviewer attention

#### Scenario: Gaps in a sequence are detectable
- **WHEN** events with sequence numbers 1, 2 and 4 arrive from one agent
- **THEN** consumers can determine that exactly one event is missing

### Requirement: Subject is pseudonymous by default
Every `Event` SHALL identify its subject by a **stable pseudonymous ID**, not by a username,
email address or system UID. The mapping from pseudonymous ID to a real identity SHALL live
outside the event stream and be resolvable only through an audited lookup.

Stability matters because peer-baseline analytics (D23) must be possible later without a schema
migration; pseudonymity matters because the event stream is the thing most widely copied,
retained and queried.

#### Scenario: No direct identifier in the event stream
- **WHEN** any Event is serialized
- **THEN** no field contains a username, email address, or OS-level UID
- **AND** this is proven by a test that scans the serialized bytes of a battery of fixture
  events for the fixture's known identity strings, not by field-by-field inspection

#### Scenario: Subject ID is stable across sessions
- **WHEN** the same subject generates events in two different login sessions on one host
- **THEN** the pseudonymous subject ID is identical in both

### Requirement: Purpose tagging
Every `Event` SHALL carry a purpose tag declaring why it was collected. Consumers SHALL be able
to filter by purpose, and the policy engine SHALL refuse to evaluate an Event under a policy
whose declared purpose does not match.

This is a data-protection requirement (D20), and it is a schema-level field rather than a
convention because purpose limitation that depends on discipline is not purpose limitation.

#### Scenario: Purpose mismatch is refused
- **WHEN** an Event tagged `PURPOSE_DLP` is evaluated against a policy declaring
  `PURPOSE_INSIDER_RISK`
- **THEN** evaluation is refused and the refusal is recorded

### Requirement: Events carry no file content
An `Event` SHALL NOT contain file contents, document fragments, clipboard contents, or any
field capable of holding them. Events carry metadata and references; content stays on the
endpoint (D10).

#### Scenario: No content-bearing field exists
- **WHEN** the Event message definition is inspected by a schema test
- **THEN** it contains no `bytes` field other than explicitly allowlisted opaque identifiers,
  and the allowlist is asserted in the test so that adding a new `bytes` field fails CI

### Requirement: Path representation is deferred pending measurement
The `Event` message SHALL represent the subject of a filesystem event in a form that can carry
either a resolved path or an opaque kernel file handle, because which of these is available has
not yet been established.

**This requirement is explicitly provisional.** Ticket T-005 (fanotify observe spike) will
determine whether the agent receives resolvable paths or only handles requiring
`open_by_handle_at`. If T-005 contradicts this representation, this spec is revised before any
consumer is built on it.

#### Scenario: Both representations are expressible
- **WHEN** a filesystem Event is constructed from a resolved path
- **THEN** it validates
- **WHEN** a filesystem Event is constructed from an opaque handle with no resolved path
- **THEN** it also validates, and consumers can distinguish the two cases
