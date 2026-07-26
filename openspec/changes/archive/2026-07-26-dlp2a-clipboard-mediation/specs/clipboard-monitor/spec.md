## ADDED Requirements

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
