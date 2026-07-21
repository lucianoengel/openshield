## Context

The repo is a single Go module. Boundary checks already exist as `go list -deps` scripts
(`check-core-deps.sh`, `check-capability-boundary.sh`) wired into the `invariants` CI job. No
managed/enterprise code exists yet. D21 wants the open-core line drawn before it does.

## Goals / Non-Goals

**Goals:**
- Reserve `internal/enterprise/...` for non-open code and enforce that the open tree never imports
  it (one-way boundary).
- Prove the check fires on a planted violation, so a vacuous green does not mislead.

**Non-Goals:**
- Writing enterprise code, a license model, or a distribution split (deferred, D21).
- Forbidding the directory's existence; the import-direction check is the enforcement.

## Decisions

### One-way import check
`scripts/check-opencore-boundary.sh`: for every open package (`go list ./...` minus anything under
`internal/enterprise`), compute deps and fail if any dep is under
`.../internal/enterprise`. Enterprise → open is allowed (open-core); open → enterprise is not.

### Prove it fires
A test (or a scripted CI step) temporarily creates a throwaway open package importing the reserved
prefix and asserts the check exits non-zero, then removes it. Rather than mutate the tree in CI, a
Go test `internal/enterprise/boundary_test.go`-style approach is fragile; instead the proof is a
self-contained shell assertion in the check's own test: create a temp package under a temp GOPATH?
Simpler and honest: a Go test that runs the script against a tiny fixture module is overkill.

Chosen: the check script has a `--selftest` mode that, in a temp dir, writes a minimal module with
an open package importing a fake enterprise package and asserts the detection logic flags it. This
keeps the proof next to the check without mutating the real tree. If `--selftest` is too much, the
fallback is a documented manual proof; but an unproven boundary check is exactly the vacuous-green
risk this ticket calls out, so the selftest is preferred.

### Namespace is reserved by convention + README note
A short note in `internal/enterprise/README.md` (the only file there for now) states the rule:
nothing outside this tree may import it; it may import the open core. That file's presence also
documents the reserved namespace for a future contributor.

## Risks / Trade-offs

- **Vacuous until enterprise code exists.** Mitigated by the selftest proving the check fires.
- **Convention, not hard tooling.** Same stance as the other boundary checks; a reviewed speed
  bump, stated as such.
- **A single-module repo means the split is logical, not physical.** A future physical split
  (separate module/repo) is a larger move; this logical boundary is the cheap first step D21 asked
  for, and it makes the eventual physical split mechanical rather than archaeological.
