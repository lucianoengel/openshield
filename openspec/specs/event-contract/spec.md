

## Purpose

The Event: what a producer may say and what it may never carry. Every event has an identity and
provenance, a pseudonymous subject by default, and a purpose tag; none carries file content. It covers
the subject shapes the pipeline understands — filesystem, network flow, process exec, clipboard — so a
new producer adds a subject rather than a new pipeline.

## Requirements

### Requirement: The event contract expresses a clipboard copy, content-free

The event contract SHALL include a clipboard-copy event kind and a clipboard subject shape carrying only
the copied byte count and the display server it came from. The clipboard subject SHALL NOT contain any
field capable of carrying the copied content — no bytes field, no text field — so a clipboard event cannot
express content even by mistake (D10/D29).

The existing guard that every bytes field in the Event tree is explicitly allowlisted SHALL continue to
pass WITHOUT adding an entry, which is the mechanical proof that this addition carries no content.

#### Scenario: The clipboard subject cannot carry content
- **WHEN** the Event message tree is walked for bytes fields
- **THEN** the clipboard subject contributes none, and the allowlist is unchanged

#### Scenario: A clipboard event is distinguishable by kind
- **WHEN** a clipboard event is produced
- **THEN** its kind identifies it as a clipboard copy, so a policy and a correlation rule can select it

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

<!-- restored from 2026-07-20-add-event-decision-contract -->

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

<!-- restored from 2026-07-20-add-event-decision-contract -->

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

<!-- restored from 2026-07-20-add-event-decision-contract -->

### Requirement: Events carry no file content
An `Event` SHALL NOT contain file contents, document fragments, clipboard contents, or any
field capable of holding them. Events carry metadata and references; content stays on the
endpoint (D10).

#### Scenario: No content-bearing field exists
- **WHEN** the Event message definition is inspected by a schema test
- **THEN** it contains no `bytes` field other than explicitly allowlisted opaque identifiers,
  and the allowlist is asserted in the test so that adding a new `bytes` field fails CI

<!-- restored from 2026-07-20-add-event-decision-contract -->

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

<!-- restored from 2026-07-20-add-event-decision-contract -->

### Requirement: An Event can describe a network flow or request, metadata only
The Event contract MUST be able to describe a network flow or L7 request as a target variant carrying
connection/request METADATA only — an opaque flow handle (the enforce target), the 5-tuple, protocol,
and L7 metadata (host, method, path, direction) — and MUST NOT carry the body content, which stays in
the classifying process and never crosses the boundary (D10/D29), as file content stays in the worker.

#### Scenario: A network Event carries metadata, never the body
- **WHEN** a network flow / HTTP request Event is constructed
- **THEN** it carries the flow handle and connection/request metadata and no body content
- **AND** a test confirms the Event type exposes no body/content field

<!-- restored from 2026-07-21-network-flow-contract -->

### Requirement: A process-exec subject can carry the observed process start-time

A process-exec event's subject MUST be able to carry the observed process's start-time (a monotonic
per-process value such as the kernel start-time in clock ticks), alongside the pid, so that a
consumer can distinguish the specific observed process instance from a later process that reuses the
same pid. The field MUST be optional — an event whose producer could not read the start-time carries
it absent (zero), and a consumer MUST treat absent as "identity unknown" rather than as a match. The
start-time is timing metadata, not process content — no file or memory content crosses the boundary.

#### Scenario: The process subject distinguishes a reused pid
- **WHEN** two process-exec events carry the same pid but different start-times
- **THEN** a consumer can tell they are different process instances by the start-time, and an event whose start-time is absent is treated as an unknown identity, not as matching any instance

<!-- restored from 2026-07-22-hips7-pid-reuse-revalidation -->
