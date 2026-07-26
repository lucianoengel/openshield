# clipboard-monitor Specification

## Purpose
Watching the CLIPBOARD as an exfiltration channel (DLP-2a) — the one a desktop user actually reaches for.
A copy is captured through a replaceable OS seam (subprocess helpers, not in-process display bindings),
bounded and deduplicated, and its content is classified in the SANDBOXED WORKER while the Event itself stays
content-free. The producer disables itself loudly when it cannot work, because a monitor that silently
observes nothing is worse than an absent one.

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

### Requirement: The producer disables itself loudly when it cannot work

When no display server is detected, or the required helper binary is absent, the producer SHALL NOT start
and SHALL say so — it SHALL NOT run in a state where it silently observes nothing. The engine SHALL still
start normally without clipboard monitoring.

#### Scenario: No display means no producer
- **WHEN** neither a Wayland nor an X11 display is present in the environment
- **THEN** clipboard monitoring is reported as unavailable and is not started
- **AND** the engine runs normally without it

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
