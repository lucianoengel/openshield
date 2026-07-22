## ADDED Requirements

### Requirement: CEF message parsing

The system SHALL parse an ArcSight CEF message into its seven header fields (version, device vendor,
device product, device version, signature id, name, severity) and its key=value extension map, honoring
CEF escaping — an escaped pipe in a header field, and escaped `=`, backslash, and newline in an extension
value — and preserving spaces within an extension value. A message without the `CEF:` prefix, with fewer
than seven header fields, or exceeding the line bound MUST be rejected with an error, never returned as a
partial record.

#### Scenario: A canonical CEF line parses to headers and extension

- **WHEN** a well-formed CEF line is parsed
- **THEN** the seven header fields and each extension key=value are returned, with a space-containing
  value kept whole

#### Scenario: Escapes are decoded

- **WHEN** a CEF line contains an escaped pipe in a header and an escaped `=`/backslash/newline in an
  extension value
- **THEN** the parsed fields and values contain the literal decoded characters

#### Scenario: A malformed message is rejected

- **WHEN** a line lacks the `CEF:` prefix, has fewer than seven header fields, or exceeds the bound
- **THEN** parsing returns an error and no partial record
