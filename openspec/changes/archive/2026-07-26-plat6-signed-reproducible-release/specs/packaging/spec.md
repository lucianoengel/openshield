## ADDED Requirements

### Requirement: A release build is reproducible

Building the same commit twice with the release procedure SHALL produce byte-identical artifacts. Build
flags SHALL exclude anything that varies between builds — absolute paths, build timestamps and VCS state
that is not the commit itself.

Reproducibility is what makes a signature meaningful: without it, nobody but the signer can establish that
an artifact corresponds to the source, and the signature attests only that the signer had *a* binary.

#### Scenario: Two builds of one commit agree
- **WHEN** the same commit is built twice with the release procedure
- **THEN** the artifacts' digests are identical

#### Scenario: Build metadata does not leak the build environment
- **WHEN** a release artifact is inspected
- **THEN** it contains no absolute path from the machine that built it

### Requirement: A release carries a signed digest manifest

A release SHALL include a manifest naming every artifact with its SHA-256 digest, and a detached signature
over that manifest. Signing the manifest rather than each artifact means one signature covers the set —
including which artifacts exist, so an artifact cannot be *added* to a release unnoticed.

#### Scenario: The manifest covers every shipped artifact
- **WHEN** a release is produced
- **THEN** every artifact in it appears in the manifest, and every manifest entry exists

#### Scenario: The manifest signature verifies
- **WHEN** the manifest is checked against the release public key
- **THEN** verification succeeds

### Requirement: Verification fails on any tampering

Verification SHALL fail if any artifact's bytes differ from its recorded digest, if the manifest differs
from what was signed, or if an artifact named in the manifest is absent. A failure SHALL name what did not
match.

#### Scenario: A modified artifact is rejected
- **WHEN** one artifact's bytes are altered
- **THEN** verification fails and names that artifact

#### Scenario: A modified manifest is rejected
- **WHEN** the manifest is altered after signing
- **THEN** signature verification fails

#### Scenario: An artifact added after signing is rejected
- **WHEN** a file is added to the release directory that the manifest does not name
- **THEN** verification reports it rather than ignoring it

### Requirement: The signing key never ships

The private signing key SHALL NOT appear in the repository or in the release output. Only the public key
is distributed.

#### Scenario: The release output contains no private key
- **WHEN** a release is produced
- **THEN** no private key material is present in its output
