# network-gateway delta

## ADDED Requirements

### Requirement: The interception CA is hot-rotatable, fail-safe
The cert minter MUST support replacing the interception CA at runtime: validate the new CA first,
then atomically swap it and flush the leaf cache so no leaf signed by the previous CA is served
afterward. A rotation with an invalid CA MUST fail without changing the active CA, so a bad rotation
never breaks interception or silently disables it. Rotation MUST be safe under concurrent minting.

#### Scenario: After rotation, leaves chain to the new CA and not the old
- **WHEN** a leaf is minted for a host under CA1, then the minter is rotated to CA2, then a leaf is
  minted for the same host
- **THEN** the new leaf chains to CA2 and no longer verifies against CA1

#### Scenario: A bad rotation keeps the working CA
- **WHEN** rotation is attempted with an invalid CA
- **THEN** it returns an error and the minter continues minting valid leaves under the previous CA
