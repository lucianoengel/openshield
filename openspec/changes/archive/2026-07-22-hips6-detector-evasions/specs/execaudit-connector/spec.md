# execaudit-connector (delta)

## MODIFIED Requirements

### Requirement: The execaudit connector decodes auditd's value encodings
The execaudit connector MUST decode the value encodings auditd uses for argv and exe fields: a
double-quoted value is unquoted, and a bare hex-encoded value (auditd's form for a value containing
a space or special character) is hex-decoded, so a command whose argument contains a space reaches
detection as its real text rather than an opaque hex blob. A quoted value MUST NOT be hex-decoded.

#### Scenario: A hex-encoded argv value is decoded to its real text
- **WHEN** the connector parses an EXECVE record whose spaced argument auditd hex-encoded, and a quoted simple value
- **THEN** the hex-encoded argument is decoded to its original text while the quoted value is only unquoted
