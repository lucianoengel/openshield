# smtp-connector

## ADDED Requirements

### Requirement: The SMTP capture listener MUST be startable by configuration

A shipped binary MUST bind the SMTP capture listener when an operator configures a listen address,
and MUST feed each parsed message into the same event pipeline as file, DNS and process events.

A connector that cannot be started by any configuration is not a capability of the product,
regardless of how completely it is implemented or tested.

#### Scenario: A configured listener ingests a live session

- **WHEN** an operator configures an SMTP listen address and a client delivers a message to it
- **THEN** the message MUST enter the pipeline and produce an audit entry

#### Scenario: No configuration leaves the listener inert

- **WHEN** no SMTP listen address is configured
- **THEN** no listener is bound, and the rest of the engine runs unchanged

### Requirement: An email body MUST be classified like any other content

The body of a captured message MUST be classified by the same content path as a file, and a
checksum-backed detection in an email body MUST reach a decision.

#### Scenario: A message carrying sensitive content alerts

- **WHEN** a captured message's body contains a checksum-valid identifier
- **THEN** the decision MUST be an alert, and an audit entry MUST be recorded

#### Scenario: The message body does not reach the ledger

- **WHEN** a message carrying sensitive content is decided upon
- **THEN** no audit entry may contain the body's sensitive value

### Requirement: The listener MUST state its limits when it starts

On binding, the connector MUST report that it is a capture listener rather than a mail transfer
agent, that it does not handle TLS-negotiated sessions, and that it is observe-only.

An operator who points production mail at a capture listener, or who expects a STARTTLS client to be
inspected, is wrong in a way that only surfaces later — as undelivered mail, or as a channel that
silently inspects nothing.

#### Scenario: Enabling the listener announces what it is not

- **WHEN** the SMTP listener binds
- **THEN** its startup output MUST state that it is not an MTA and does not handle TLS
