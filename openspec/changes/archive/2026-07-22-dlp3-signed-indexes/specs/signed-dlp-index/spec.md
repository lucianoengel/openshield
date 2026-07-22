## ADDED Requirements

### Requirement: Signed index authoring and verification

The system SHALL provide a way to SIGN a serialized DLP index with an operator key and to VERIFY a
signed index against a trusted operator public key before use. Verification SHALL be fail-closed: a
missing, tampered, wrong-key, or wrong-kind signed index SHALL return an error and NO index. The
signature SHALL bind the index KIND, so a signed index of one kind cannot be accepted as another.

#### Scenario: A correctly signed index verifies
- **WHEN** an operator signs an EDM index with their key and it is verified against the matching public key for kind "edm"
- **THEN** verification returns the original index bytes

#### Scenario: A tampered signed index is rejected
- **WHEN** any byte of a signed index (payload or signature) is altered
- **THEN** verification returns an error and no index bytes

#### Scenario: A wrong key is rejected
- **WHEN** a signed index is verified against a public key other than the signer's
- **THEN** verification returns an error and no index bytes

#### Scenario: A kind mismatch is rejected
- **WHEN** an index signed as kind "edm" is verified requiring kind "idm"
- **THEN** verification returns an error and no index bytes

### Requirement: The worker verifies indexes before loading them into the sandbox

When an operator index public key is configured, the worker SHALL load a configured EDM, record, or IDM
index ONLY after it verifies as a signed index of the matching kind against that key. A file that is
unsigned, tampered, wrong-key, or the wrong kind SHALL abort worker startup rather than load an
unverified index. When no key is configured, the worker MAY load an unsigned index but SHALL log a
prominent warning that the index is unverified (the ADR-9 gap).

#### Scenario: Signed index loads under a configured key
- **WHEN** the worker is configured with an operator index public key and a correctly-signed EDM index
- **THEN** the EDM detector is active with that index

#### Scenario: Unsigned index aborts under a configured key
- **WHEN** the worker is configured with an operator index public key and an UNSIGNED (or tampered) index file
- **THEN** the worker refuses to start rather than load the unverified index

### Requirement: Operator index-builder tool

The system SHALL provide an operator tool that builds an EDM, multi-cell record, or IDM index from
operator input and signs it with the operator key, emitting bytes the worker verifies and loads. The
tool SHALL reject malformed input rather than emit a partial index.

#### Scenario: Build and sign round-trips through the worker's verifier
- **WHEN** the operator builds and signs an index of a given kind from valid input
- **THEN** verifying the output with the corresponding public key and kind yields loadable index bytes
- **AND** the resulting index detects the operator's seeded values
