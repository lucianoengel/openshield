# e2e-verification

## ADDED Requirements

### Requirement: Resources created inside a running stack are per-test too

A database, schema or other named resource that a scenario creates INSIDE the shared stack SHALL be
scoped to the creating test, so two scenarios asking for the same label receive different resources.

The suite already refuses fixed ports and fixed names for infrastructure it STARTS. A resource created
inside a running stack was not covered, and a convention of "pick a name nobody else used" is enforced by
nothing: it fails only when the whole suite runs, which under a targeted-test workflow means it fails
first in CI.

#### Scenario: Two scenarios asking for the same label do not collide
- **WHEN** two scenarios each create a resource under the same caller-supplied label
- **THEN** each receives its own, and neither fails because the other exists

#### Scenario: A long test name still yields a usable identifier
- **WHEN** the scoped name would exceed the store's identifier limit
- **THEN** it is shortened so that names sharing a long prefix remain distinct, and the caller's label is
  preserved
