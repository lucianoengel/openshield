# Add the open-core separability boundary (T-021)

## Why

D21 committed to keeping the managed Hub, compliance packs and multi-tenant control plane
cleanly separable from the open core — NOW, while it is cheap, because retrofitting a boundary
after code has grown across it is expensive. None of that closed/managed code exists yet, which
is exactly why the boundary should be drawn before it does: the first commit of enterprise code
must land on the correct side of a line that already exists and is enforced, not have the line
drawn around it afterwards.

## What changes

**A reserved package namespace for non-open code and a CI check that the open tree never imports
it.** Convention: managed/enterprise/closed code lives under `internal/enterprise/...` (Hub
serving, compliance packs, multi-tenant control plane). The open packages — everything else under
`internal/` and `cmd/` — MUST NOT import anything under that prefix. A `go list`-based check
fails the build on a violation, the same shape as the core-dependency and capability-boundary
checks already in CI.

**The direction is one-way and that is the point.** Open code may not depend on enterprise code
(or the open distribution would not build without it); enterprise code may depend on the open
core (that is what open-core means). The check enforces exactly that asymmetry.

**Proven by a planted violation, not by vacuous green.** With no enterprise code yet the check
passes trivially, which on its own would give false confidence. So a test plants an import of the
reserved prefix and asserts the check FIRES — the guard is demonstrated to work before it has
anything real to guard, so the boundary is enforced from the first line of enterprise code.

## What this does NOT claim or cover

- **It does not create any enterprise code or a sustainability model.** Both are explicitly
  deferred (D21). This draws the line; it does not decide what goes on the far side of it.
- **It does not enforce a license boundary.** It is an import-direction check; what license the
  enterprise packages carry, and how they are distributed, is a separate decision for when they
  exist.
- **It does not stop a determined refactor from moving the line.** Like the other boundary checks,
  it is a deliberate speed bump that makes crossing the boundary a conscious, reviewed act — not a
  cryptographic guarantee.
- **It reserves a namespace by convention, not by tooling that forbids the directory.** The check
  is the enforcement; the directory not existing yet is fine.

## Decisions

Depends on **D21** (design for open-core separability now; a CI import test costs one ticket) and
mirrors the existing boundary checks (D24 core-dependency, D26/T-014 capability-direction).

No new decision — this implements D21's "CI import test" with a named reserved namespace.
