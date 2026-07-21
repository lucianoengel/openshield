# smtp-connector delta

## ADDED Requirements

### Requirement: The SMTP connector parses a session into an envelope and a classifiable body
The connector MUST parse an SMTP client transcript into the envelope sender and recipients
and the DATA message body, applying dot-unstuffing and ending the body at the lone-dot
terminator, and MUST reject a session with no sender, no recipient, or an unterminated DATA
block — never returning a partial message as complete. The message body MUST be available
for classification but MUST NOT be placed in the event; the event MUST carry only envelope
metadata (the recipient domain), never a full recipient address or the body.

#### Scenario: A session yields a classifiable body and domain-only metadata
- **WHEN** the connector parses an SMTP session carrying sensitive content
- **THEN** the body is extracted (dot-unstuffed, terminator-bounded) and its PII is detected by the classifier, the event carries the recipient domain but not the full address or body, and a malformed session is rejected
