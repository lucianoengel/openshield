

## Purpose

Clipboard DLP: copy is captured when it happens and attributed to its source application, and where the
display server permits it the clipboard is MEDIATED so a paste is decided at paste time against its
destination. Excluded sources — password managers — are never read at all, the exclusion applying BEFORE
the read. Capability is reported per display server and never overstated, and a failing mediator must
release the selection rather than take the clipboard down with it.

## Requirements

### Requirement: The clipboard is mediated, and a paste is decided at paste time

The system SHALL take ownership of the clipboard selection and answer paste requests itself, so that a
paste is DECIDED rather than merely observed. When policy denies a paste, the requesting application SHALL
NOT receive the content.

The decision SHALL be made per REQUEST, so the same clipboard content can be released to one destination
and refused to another. Every enforced refusal SHALL be recorded with the same severity discipline as any
other enforcement.

#### Scenario: A denied paste yields nothing
- **WHEN** sensitive content is on the clipboard and a destination the policy denies requests it
- **THEN** the requesting application receives no content
- **AND** the test FAILS if the content is served regardless of the decision

#### Scenario: An allowed destination still receives the content
- **WHEN** the same content is requested by a destination the policy allows
- **THEN** the content is served unchanged
- **AND** the test FAILS if mediation degrades into blocking everything

### Requirement: A copy is captured when it happens, and attributed to its source

On a display server that reports selection-ownership changes, capture SHALL be event-driven rather than
polled, so a copy is seen when it occurs and a copy replaced quickly is not missed.

The system SHALL attribute a copy to the application that made it, where the display server exposes that.

#### Scenario: A copy is observed without polling
- **WHEN** an application takes ownership of the clipboard
- **THEN** the copy is captured on the ownership-change notification, with no polling interval involved

#### Scenario: The copying application is identified
- **WHEN** a copy is captured on a display server that exposes the owning window's process
- **THEN** the event carries the copying application's executable path

### Requirement: A paste is attributed to its destination where the protocol allows it

Where the display protocol identifies the requesting client, the system SHALL resolve it to the pasting
application and make it available to the policy as the DESTINATION of the transfer.

Where the protocol does NOT identify the requesting client, the system SHALL report destination attribution
as unavailable and the policy SHALL decide without it. It SHALL NOT invent, guess, or infer a destination:
a fabricated destination in an enforcement decision is worse than an absent one.

#### Scenario: The pasting application is identified where the protocol allows
- **WHEN** a paste request arrives on a display server that names the requesting client
- **THEN** the destination application's executable path is available to the policy

#### Scenario: An unattributable destination is reported as unknown
- **WHEN** the display protocol does not identify the requesting client
- **THEN** the destination is reported as unknown rather than inferred
- **AND** the capability is reported honestly rather than claimed

### Requirement: Excluded sources are never read

A copy from an excluded source SHALL NOT be read, classified, or recorded. Exclusion SHALL be applied
BEFORE capture, not as a filter on results: reading a password out of a vault and then discarding the
classification still means the secret was read into the monitoring process.

Password managers SHALL be excluded by default, and an operator SHALL be able to extend the list.

#### Scenario: A password-manager copy is not read
- **WHEN** the copying application is on the exclusion list
- **THEN** the clipboard content is never read and no event is produced
- **AND** the test FAILS if the content is read and only then discarded

### Requirement: A failing mediator must not take the clipboard with it

If mediation cannot start, or fails while running, the clipboard SHALL keep working normally: the system
SHALL relinquish or never take ownership rather than leave the user unable to paste. A monitoring component
must never be able to break the desktop's clipboard (D17).

#### Scenario: A mediator that stops leaves a working clipboard
- **WHEN** mediation stops or fails
- **THEN** the clipboard continues to function for the user
- **AND** the test FAILS if a stopped mediator leaves the selection owned and unanswered

### Requirement: Capability is reported per display server, never overstated

The system SHALL report which clipboard capabilities are actually available on the running display server —
capture, source attribution, destination attribution, enforcement — and SHALL NOT claim a capability the
protocol does not provide.

#### Scenario: Reported capabilities match the display server
- **WHEN** clipboard mediation starts
- **THEN** it reports exactly the capabilities it obtained, including which are unavailable and why

### Requirement: A clipboard change produces a content-free event whose content reaches only the classifier

The system SHALL emit an event when the clipboard's contents change, and that event SHALL carry METADATA
ONLY — a byte count and the display server — never the copied text (D10/D29). The copied bytes SHALL be
made available to the classification stage so they are parsed in the SANDBOXED WORKER, and SHALL NOT be
placed in the event, the classification summary, or any record that crosses the host boundary.

This SHALL be proven by a test that seeds recognizable PII into the clipboard and asserts the SERIALIZED
event bytes do not contain it, while the classification for that event does report the corresponding
detector hit.

#### Scenario: A sensitive copy is classified without the event carrying it
- **WHEN** clipboard content containing a recognizable national ID is captured
- **THEN** the classification for that event reports the corresponding detector type
- **AND** the serialized event contains none of the copied text
- **AND** the test FAILS if the copied text is placed in the event, or if the content is not supplied to
  the classifier at all

#### Scenario: The event's metadata describes the copy
- **WHEN** a clipboard copy is captured
- **THEN** the event reports the copied byte count and which display server it came from

<!-- restored from 2026-07-26-dlp2a-clipboard-producer -->

### Requirement: The clipboard is read through a replaceable seam, never in-process display bindings

Reading the clipboard SHALL go through a seam with an OS-specific implementation, so the capture mechanism
is replaceable and testable without a display. The Linux implementations SHALL invoke the host's clipboard
helpers as subprocesses rather than linking display-server bindings into the process, and the argument
vectors SHALL be independently testable.

On a platform with no implementation, the seam SHALL return a clear unsupported error rather than silently
reporting an empty clipboard — an empty read and an unavailable reader are different facts.

#### Scenario: Each backend builds the right command
- **WHEN** the Wayland and X11 backends' argument vectors are constructed
- **THEN** each names its helper binary and requests the clipboard selection

#### Scenario: An unsupported platform says so
- **WHEN** the clipboard is read on a platform with no implementation
- **THEN** it returns an unsupported error, distinct from an empty clipboard

<!-- restored from 2026-07-26-dlp2a-clipboard-producer -->

### Requirement: The producer disables itself loudly when it cannot work

When no display server is detected, or the required helper binary is absent, the producer SHALL NOT start
and SHALL say so — it SHALL NOT run in a state where it silently observes nothing. The engine SHALL still
start normally without clipboard monitoring.

#### Scenario: No display means no producer
- **WHEN** neither a Wayland nor an X11 display is present in the environment
- **THEN** clipboard monitoring is reported as unavailable and is not started
- **AND** the engine runs normally without it

<!-- restored from 2026-07-26-dlp2a-clipboard-producer -->

### Requirement: Reads are bounded and repeats are not re-reported

A clipboard read SHALL be capped at a maximum size, so a very large clipboard cannot exhaust the memory of
the process that forwards it. Content beyond the cap SHALL be truncated rather than read whole.

Unchanged clipboard content SHALL NOT emit repeated events across polls: the producer SHALL detect that the
content is the same as the last observed content. Any digest used for that comparison is LOCAL DEDUP STATE
ONLY and SHALL NOT be emitted, logged, or transmitted — a transmitted digest of low-entropy content would
be a privacy claim the project explicitly rejects (D10/D11).

#### Scenario: An oversized clipboard is truncated
- **WHEN** the clipboard holds more than the maximum readable size
- **THEN** the read returns exactly the cap, not the whole content
- **AND** the test FAILS if the cap is removed

#### Scenario: The same content polls once
- **WHEN** the clipboard is polled repeatedly with unchanged content
- **THEN** exactly one event is emitted
- **AND** a subsequent change emits a second event
- **AND** the test FAILS if the change detection is removed

<!-- restored from 2026-07-26-dlp2a-clipboard-producer -->

### Requirement: Supplying content to the classifier must not displace another producer's content

The mechanism that supplies out-of-band content to the classify stage SHALL support more than one producer:
installing the clipboard producer's content source SHALL chain to any already-installed source rather than
replacing it. Registered content SHALL be bounded and released after use, so a producer cannot grow memory
without limit.

#### Scenario: A pre-existing content source still works
- **WHEN** another content source is already installed and the clipboard producer installs its own
- **THEN** both sources resolve their own events' content
- **AND** the test FAILS if the installation overwrites the existing source

#### Scenario: Registered content is released
- **WHEN** an event's content has been resolved
- **THEN** it is no longer retained

<!-- restored from 2026-07-26-dlp2a-clipboard-producer -->
