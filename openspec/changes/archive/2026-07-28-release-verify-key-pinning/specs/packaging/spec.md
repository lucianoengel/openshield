# packaging

## ADDED Requirements

### Requirement: Release verification MUST support an out-of-band pinned signing key

The release verification command MUST accept an operator-supplied ed25519 public key and, when one is
supplied, MUST verify the release manifest's signature against THAT key.

The public key file distributed inside the release directory MUST NOT be consulted when a pinned key
is supplied, under any condition — including the pinned key being unreadable or malformed, which MUST
be a hard failure rather than a fallback.

#### Scenario: A release re-signed with another key is refused under a pinned key

- **WHEN** an attacker modifies an artifact and re-signs the entire release with a key of their own,
  replacing the public key shipped in the release directory
- **AND** an operator verifies with a pinned key naming the project's real public key, obtained out of band
- **THEN** verification MUST fail, naming the signature as the reason

#### Scenario: A genuine release verifies under its pinned key

- **WHEN** a release is verified with a pinned key corresponding to the key that signed it
- **THEN** verification MUST succeed

#### Scenario: A malformed pinned key is a hard failure

- **WHEN** the pinned key file cannot be read or is not an ed25519 public key
- **THEN** the command MUST fail
- **AND** MUST NOT fall back to the public key shipped inside the release directory

### Requirement: Unpinned release verification MUST state what it did not establish

When no pinned key is supplied, the release verification command MUST report that it checked the
integrity of the artifact set and did NOT establish that the project signed it, and MUST say how to
check authenticity.

This is the D31 rule applied to the supply chain: an operator who runs a verification command and
sees success will believe the strongest claim the command could plausibly be making, so a limit that
is not stated becomes a false belief.

#### Scenario: Verifying without a pinned key announces the limit

- **WHEN** a release is verified with no pinned key
- **AND** the artifact set is internally consistent
- **THEN** the command MUST succeed
- **AND** MUST report that authenticity was not established and that a pinned key establishes it

### Requirement: Release verification MUST report the key it verified against

The verification command MUST report a fingerprint of the public key whose signature it accepted, so
that two operators can establish they verified against the same key rather than each against whatever
key was shipped to them.

#### Scenario: The verified key is identifiable in the output

- **WHEN** a release verifies successfully, pinned or unpinned
- **THEN** the output MUST include a fingerprint of the public key that was used
