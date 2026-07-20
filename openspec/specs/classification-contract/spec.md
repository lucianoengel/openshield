# Classification Contract

## Purpose

The boundary between what the endpoint knows locally and what may cross the host boundary. Two distinct types rather than one type with a redaction step, because redaction is a runtime behaviour that gets skipped and a type boundary is not.

> Synced from change `add-event-decision-contract` on 2026-07-20.
> Implemented in `internal/core`. The invariants below are enforced by tests
> (`schema_test.go`, `privacy_test.go`, `validate_test.go`, `compile_test.go`),
> each mutation-tested — a schema test that never fails is indistinguishable from
> no test.

## Requirements
### Requirement: Local and wire classification forms are separate types
Classification output SHALL be represented by two distinct messages: `LocalClassification`,
which never leaves the host, and `ClassificationSummary`, which is the only form permitted to
cross the host boundary.

They are separate types rather than one type with a redaction step because a redaction step is
a runtime behaviour that can be forgotten, bypassed or regressed. Two types make the mistake a
compile error (D10).

#### Scenario: The wire type cannot express content
- **WHEN** the `ClassificationSummary` definition is inspected by a schema test
- **THEN** its fields are exactly: detector type, confidence, match count, and the ID of the
  Event it describes
- **AND** it contains no string or bytes field capable of holding a match, an excerpt, a hash,
  a fingerprint or an embedding

#### Scenario: Transport accepts only the wire type
- **WHEN** the agent-to-control-plane interface is inspected
- **THEN** it accepts `ClassificationSummary` and has no method accepting
  `LocalClassification`
- **AND** attempting to send a `LocalClassification` is a compile error

### Requirement: No reversible representation of low-entropy identifiers leaves the host
The system SHALL NOT transmit an exact-match hash, keyed or unkeyed, of a low-entropy
identifier — including national identifiers such as CPF and SSN, payment card numbers, phone
numbers and dates of birth.

Hashing these is not a privacy control. Their keyspaces (CPF and SSN ~10⁹, cards ~10⁷ after BIN
and Luhn constraints, dates of birth ~36.5k) are exhaustively searchable in minutes to hours,
and salting does not help once the salt is known — which it must be, on every endpoint, for
cross-host matching to work at all (D10).

#### Scenario: Seed values do not appear in transmitted bytes
- **WHEN** a file containing known fixture CPF, SSN and card values is classified
- **AND** the resulting `ClassificationSummary` is serialized
- **THEN** scanning the serialized bytes finds no substring of any fixture value
- **AND** scanning also finds no MD5, SHA-1, SHA-256 or HMAC digest of any fixture value,
  computed over the fixture set at test time

#### Scenario: Match count conveys quantity, not identity
- **WHEN** a document contains four distinct card numbers
- **THEN** the summary reports a count of four and a detector type
- **AND** carries nothing that distinguishes which four

### Requirement: Embeddings and similarity fingerprints are content
Embeddings, similarity-preserving hashes and fuzzy fingerprints SHALL be treated as
content-equivalent: they may exist in `LocalClassification`, SHALL NOT appear in
`ClassificationSummary`, and SHALL NOT be distributed through the Hub.

These are not de-identification techniques. Similarity-preserving hashes leak structure by
construction — that is what makes them useful — and dense embeddings are invertible, with
published attacks recovering around 92% of short inputs exactly (D11).

#### Scenario: The wire type has no embedding field
- **WHEN** the `ClassificationSummary` definition is inspected
- **THEN** it contains no vector, float array, or fingerprint field

### Requirement: Detector types are enumerated, not free-form
`ClassificationSummary.detector_type` SHALL be a closed enum. Adding a detector type SHALL
require a schema change.

A free-form string would let a detector name leak the thing it detected — for example a
detector named after a specific customer, project or individual — reintroducing the content
leak the summary type exists to prevent.

#### Scenario: Detector type cannot carry arbitrary text
- **WHEN** the definition is inspected
- **THEN** `detector_type` is an enum, not a string

### Requirement: Classification runs outside the privileged process
The classification pipeline SHALL execute in a process that holds no elevated capabilities and
has no network access. The privileged process SHALL receive only structured verdicts across the
boundary.

A root process holding `CAP_SYS_ADMIN` that also parses attacker-controlled documents converts
any parser memory bug into host compromise — the failure mode behind repeated RCEs in
comparable security products (D13).

#### Scenario: The privileged process cannot parse
- **WHEN** the dependency graph of the privileged binary is computed by CI
- **THEN** it contains no package from `encoding/*`, `compress/*` or `archive/*`, and no
  document-parsing dependency
- **AND** the check fails the build rather than emitting a warning
