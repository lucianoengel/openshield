## ADDED Requirements

### Requirement: Every package is reachable from a shipped binary, or carries a recorded reason

The gate SHALL fail when a package in the module is reachable from no `cmd/` binary and is not listed
with a reason for being outside that closure. It SHALL also fail when a listed package has become
reachable, so the list cannot accumulate entries nobody reads.

This project's most frequent defect is not a wrong line — it is a complete, unit-tested, documented
package that no binary imports, and therefore cannot run in any deployment however configured. Unit
tests cannot detect it, because a package's tests import the package and pass whether or not anything
else does; `go build ./...` cannot either, because it compiles a library nothing links. The import
closure of `cmd/` is the only cheap signal.

Reasons SHALL name a category, and a platform-gated entry SHALL name the file that imports it, so the
claim can be re-checked rather than trusted.

#### Scenario: A new package that nothing imports
- **WHEN** a package is added and no binary imports it, directly or transitively
- **THEN** the gate fails and names the package

#### Scenario: A listed package becomes wired
- **WHEN** a package recorded as outside the closure is imported by a binary
- **THEN** the gate fails, requiring the stale entry to be removed

#### Scenario: A package wired only on a non-Linux platform
- **WHEN** a package is imported solely by a `!linux`-tagged file
- **THEN** it is outside the closure as computed on Linux, and its recorded reason names the
  importing file

### Requirement: What the integration suite executes is measurable and reproducible

Verification SHALL provide a repeatable command that measures which code the suite executes in the
REAL shipped binaries — instrumented builds, coverage profiles collected from each subprocess, and a
per-package report ordered lowest-coverage-first.

A number stated once in a document decays; a number anyone can re-derive does not. The measurement
also depends on the harness stopping processes with SIGTERM before SIGKILL, because a killed process
flushes no profile — a dependency that must be recorded, since a future "just kill it" simplification
would break the measurement silently rather than fail.

#### Scenario: The suite runs against instrumented binaries
- **WHEN** the coverage measurement is run
- **THEN** the suite executes the pre-built instrumented binaries and each subprocess contributes a
  coverage profile

#### Scenario: The measurement cannot report an empty result as success
- **WHEN** no coverage profile was collected, or the report parse yields no rows from a non-empty
  profile set
- **THEN** the command fails and says the measurement did not happen, rather than reporting zero

#### Scenario: The report names the least-exercised code first
- **WHEN** the measurement completes
- **THEN** per-package coverage is reported ascending, so the work list is the top of the output
