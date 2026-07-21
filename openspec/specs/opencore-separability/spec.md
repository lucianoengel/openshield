# opencore-separability Specification

## Purpose
The one-way open-core boundary: no open package may import the reserved internal/enterprise namespace (managed Hub, compliance packs, control plane), enforced by a CI check proven to fire via a self-test — drawn now, while cheap, so the first enterprise commit lands on the correct side (D21).
## Requirements
### Requirement: Open code must not import enterprise code
The open packages MUST NOT import anything under the reserved `internal/enterprise/...` namespace,
and a CI check MUST fail the build on a violation. Enterprise code MAY import the open core; the
boundary is one-way.

Open-core only works if the open distribution builds without the managed code. If an open package
imported enterprise code, the open build would break — or, worse, silently pull closed code into
the open artifact. The one-way rule is the whole separability guarantee, and D21 wants it enforced
before enterprise code exists so the first such commit lands on the correct side of the line.

#### Scenario: An open package importing enterprise code fails the build
- **WHEN** an open package imports a package under `internal/enterprise`
- **THEN** the boundary check exits non-zero and fails the build

#### Scenario: The check is proven to fire, not merely to pass
- **WHEN** the check is exercised against a planted open→enterprise import
- **THEN** it detects and reports it
- **AND** this is asserted, because a boundary check that has nothing to guard yet must be shown to
  work or its green is meaningless

#### Scenario: Enterprise-to-open is allowed
- **WHEN** enterprise code imports the open core
- **THEN** the check does not flag it, because open-core means the managed layer builds on the open
  one, not the reverse

