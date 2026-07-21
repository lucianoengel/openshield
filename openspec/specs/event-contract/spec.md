# Event Contract

## Purpose

What a producer emits into the pipeline: identity, provenance, a pseudonymous subject, a declared purpose, and the three filesystem identity forms fanotify actually delivers. Events carry metadata and references — never content.

> Synced from change `add-event-decision-contract` on 2026-07-20.
> Implemented in `internal/core`. The invariants below are enforced by tests
> (`schema_test.go`, `privacy_test.go`, `validate_test.go`, `compile_test.go`),
> each mutation-tested — a schema test that never fails is indistinguishable from
> no test.
## Requirements
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

### Requirement: Filesystem subject identity has three forms
The `Event` message SHALL represent the subject of a filesystem event as a choice of exactly
three forms, because fanotify delivers three different identities depending on the coverage mode
the agent selects (measured in [T-005](../../../../docs/spike-t005-fanotify.md)):

- `resolved_path` — classic mode, where the kernel supplies a file descriptor and the path
  follows from `readlink /proc/self/fd/N` with no further capability;
- `file_handle` — FID mode, used with a filesystem-wide mark so the kernel need not open an fd
  per event; opaque, and resolving it requires `CAP_DAC_READ_SEARCH`;
- `parent_and_name` — DFID_NAME mode, a parent-directory handle plus the filename; the name
  needs no capability, but a name alone is not a path.

Consumers SHALL be able to distinguish which form they received, and SHALL NOT assume a path is
available.

An earlier version of this requirement modelled only two forms and described itself as
provisional pending measurement. The measurement was taken; the provisional note is discharged;
the arity was wrong. Three forms is now a measured fact, not a hedge.

#### Scenario: All three identity forms are expressible
- **WHEN** an Event is constructed from a resolved path
- **THEN** it validates and reports its identity form as `resolved_path`
- **WHEN** an Event is constructed from an opaque file handle with no path
- **THEN** it validates and reports its identity form as `file_handle`
- **WHEN** an Event is constructed from a parent handle and a filename
- **THEN** it validates and reports its identity form as `parent_and_name`

#### Scenario: Consumers cannot silently assume a path
- **WHEN** a consumer requests the resolved path of an Event carrying only a file handle
- **THEN** the call returns an explicit "not available" result rather than an empty string
- **AND** a test asserts this for each of the three forms, so a consumer that ignores the
  distinction fails rather than treating a missing path as an empty one

### Requirement: An Event can describe a network flow or request, metadata only
The Event contract MUST be able to describe a network flow or L7 request as a target variant carrying
connection/request METADATA only — an opaque flow handle (the enforce target), the 5-tuple, protocol,
and L7 metadata (host, method, path, direction) — and MUST NOT carry the body content, which stays in
the classifying process and never crosses the boundary (D10/D29), as file content stays in the worker.

#### Scenario: A network Event carries metadata, never the body
- **WHEN** a network flow / HTTP request Event is constructed
- **THEN** it carries the flow handle and connection/request metadata and no body content
- **AND** a test confirms the Event type exposes no body/content field

