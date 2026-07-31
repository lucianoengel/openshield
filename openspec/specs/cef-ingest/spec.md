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

### Requirement: Newline-delimited JSON logs are ingested and huntable alongside every other source

The control plane SHALL ingest newline-delimited JSON log files from a configured directory, flattening
nested objects into dotted keys, and those records SHALL be reachable by the SAME canonical vocabulary as
CEF, CloudTrail and WEF.

CEF, CloudTrail and WEF each cover one vendor's idea of a log. JSON lines is what everything else emits —
application logs, Kubernetes, GCP audit, Azure activity, every shipper's default output. It is not one
more format: it is the difference between a SIEM that ingests three products and one that ingests an
estate. A format that ingests into its own corner is a place to put logs, not a SIEM, so the canonical
vocabulary SHALL cover the ECS dotted keys those documents use.

A DOCUMENT WITH NO RECOGNISABLE TIMESTAMP SHALL BE MARKED AS SUCH, and the count SHALL be exposed. JSON
logs have no agreed time field, so a source naming its timestamp something unrecognised has EVERY event
stamped with the moment of ingest — all present, all searchable, and all in the wrong place on the
timeline, where a time-bounded hunt misses them while reporting a clean result. Nothing else about that
source looks wrong.

Timestamp field names SHALL come from a closed list rather than a substring match: matching anything
containing "time" pulls in durations, and a duration parsed as a date is not a missing timestamp but a
confidently wrong one that sorts to the top of every descending query.

Array elements SHALL become indexed keys rather than a joined string, so an exact-match hunt cannot match
a substring spanning two elements. A JSON null SHALL be absent from the field set rather than stored as
empty, because the canonical projection reads an empty value as "this source does not carry the field".

A document that is not an object SHALL be refused rather than stored as a row with no fields. Field count,
value length and nesting depth SHALL be bounded, and a document that lost fields to a bound SHALL say so —
a partial parse that looked complete makes a hunt over the missing keys read as a finding of absence. A
branch below the depth bound SHALL be kept as its JSON text rather than dropped.

A file with SOME unparseable lines SHALL still ingest the rest, with the bad ones counted: failing the
whole file lets one truncated line discard everything before it. A file with NO parseable lines SHALL be
marked failed, so a source sending something unreadable is visible rather than emptying a directory into
nothing.

The vendor label SHALL come from configuration, not from the documents: a vendor read out of a field the
log happened to carry would split one directory's contents across facets nobody chose.

#### Scenario: A nested JSON document becomes huntable
- **WHEN** a JSON-lines file is dropped in the watched directory
- **THEN** its nested keys are flattened and the record is returned by a canonical hunt alongside the
  other sources

#### Scenario: A synthesised timestamp is declared and counted
- **WHEN** a document carries no recognisable time field
- **THEN** the record is marked as having a supplied timestamp and the counter rises

#### Scenario: A duration is not read as a timestamp
- **WHEN** a document carries a duration field whose value falls in the epoch range
- **THEN** the timestamp is still treated as absent

#### Scenario: Bad lines do not discard the good ones
- **WHEN** a file contains a mixture of parseable and unparseable lines
- **THEN** the parseable ones are stored and the rest are counted
