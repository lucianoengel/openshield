# cef-ingest Specification

## Purpose
Parse third-party security events in ArcSight CEF (Common Event Format) — the lingua franca of
firewall/IDS/WAF/endpoint logs — into structured records (vendor, product, signature, severity, and
the key=value extension), so external security logs become searchable and correlatable. A pure parser:
the untrusted-bytes surface is isolated and tested in Go; a malformed line is rejected, never a partial
record. Decodes faithfully (escaping honored), does not interpret. A live listener + search-path
persistence, and WEF/cloud-JSON parsers, are follow-ons reusing this pattern.

## Requirements

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

### Requirement: Ingested logs are huntable through one cross-vendor vocabulary

The control plane SHALL expose a closed canonical field vocabulary, and a search on a canonical name
SHALL reach every source-specific field that carries the same fact — CEF's `suser`, CloudTrail's
`userIdentityArn` and a Windows event's `SubjectUserName` SHALL all be reachable by one query for the
acting user. Each returned log SHALL carry its raw fields projected onto that vocabulary alongside, not
instead of, the raw fields.

The failure this removes is not inconvenience. A hunt that misses a source does not report that it missed
one: it returns fewer rows, and reads as a narrower blast radius. A gap in a SIEM's coverage looks exactly
like good news.

The projection SHALL be computed on READ from the stored raw fields and SHALL NOT be stored. A stored
normalisation freezes the map at the moment each log arrived, so extending it later would leave every
existing log carrying the mapping of its own era and the fix would require rewriting history.

A search on a source's OWN field name SHALL keep matching exactly what it matched before. Silently
widening a precise query is the same wrong answer as missing a source, with the sign reversed.

A canonical name a source does not carry SHALL be ABSENT from the projection rather than present and
empty — "this source has no destination IP" and "this event's destination IP was blank" are different
facts, and collapsing them lets an analyst conclude the map covers a source it does not.

Field-name matching SHALL be case-insensitive, because the source conventions collide (lower-case CEF,
PascalCase Windows EventData, camelCase CloudTrail) and exact-case matching silently misses whichever
convention the map was not written against.

The vocabulary and the source fields each canonical name covers SHALL be enumerable through the API. A
normalisation nobody can enumerate is one an analyst has to learn from the source, and publishing the
coverage is what lets "no results" be read as "not covered here" rather than "did not happen".

This SHALL remain a NAME map and SHALL NOT claim to normalise VALUES. Asserting that `CORP\alice` and
`alice@corp.example` are the same principal requires identity resolution that exists for this product's
own entities and not for arbitrary third-party logs.

#### Scenario: One hunt reaches three vendors
- **WHEN** logs from CEF, CloudTrail and Windows each record the same user under their own field name
- **AND** one search is run on the canonical user field
- **THEN** all three are returned, each carrying the canonical projection alongside its raw fields

#### Scenario: A vendor's own field name is not widened
- **WHEN** a search names a source-specific field rather than a canonical one
- **THEN** only logs carrying that exact field match

#### Scenario: An uncovered field is absent, not blank
- **WHEN** a source carries no value for a canonical name
- **THEN** that name does not appear in the projection

#### Scenario: The vocabulary is discoverable
- **WHEN** an analyst asks the API for the hunting vocabulary
- **THEN** it returns the canonical names and the source fields each one covers
