# control-plane

## ADDED Requirements

### Requirement: A paginated read reports whether more rows exist

A capped read SHALL report whether rows beyond the returned page exist, and SHALL provide the means to
continue from the end of the page.

A result truncated at a cap and presented without that signal looks complete. An analyst hunting across
retained telemetry would conclude the fleet holds nothing beyond the cap, which is a wrong answer rather
than a partial one.

#### Scenario: A truncated result says so
- **WHEN** more rows match than the page holds
- **THEN** the response reports that more exist and carries a cursor to continue from

#### Scenario: The final page offers no cursor
- **WHEN** the returned page exhausts the matching rows
- **THEN** no continuation cursor is present, rather than an empty one

### Requirement: A cursor carries position and never authority

Continuation SHALL be by a position-only cursor, and the caller's authority SHALL be re-derived from their
credential on every page.

A cursor honoured without re-deriving authority lets one operator replay another's and page through rows
they were never entitled to. Preventing this while the cursor is designed is nearly free; retrofitting it
once clients hold cursors is not.

#### Scenario: A cursor minted by one operator does not carry that operator's authority
- **WHEN** a caller presents a cursor created under a different credential
- **THEN** the page is governed by the presenting caller's own authority

#### Scenario: A caller with no credential cannot page
- **WHEN** a cursor is presented without an operator credential
- **THEN** the request is refused

### Requirement: A malformed cursor is refused rather than ignored

An unreadable cursor SHALL be refused with its reason.

Silently restarting from the beginning returns the first page to a client that believes it is deeper in
the result, so the client renders duplicates and concludes the underlying data changed.

#### Scenario: An unreadable cursor is an error
- **WHEN** a cursor cannot be decoded
- **THEN** the request is refused rather than served from the start
