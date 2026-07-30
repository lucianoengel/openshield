# Measure what the integration suite actually executes, and guard the wiring

## Why

The owner's question was direct: *"make sure every code path is covered and executed in integration
tests, so we know everything is wired, there's no gaps and works as it should."*

That question had never been answered with a number. The suite runs the real binaries against real
Postgres and NATS across ~60 files, and the only evidence that it covers the product is that it
keeps finding real defects — which is evidence of value, not of coverage. Nothing in the repository
could distinguish "this code runs in the suite" from "this code compiles and has unit tests".

**The failure mode this exists to catch is specific and has happened repeatedly.** A complete,
unit-tested, documented package that no binary imports — and therefore cannot run in any deployment
however configured. `internal/connectors/smtp` was exactly that: parser, capture listener with
per-session ceilings, idle timeouts, a concurrency cap, an event producer, full tests, and no `cmd/`
importing it, while the README described the product performing live SMTP inspection.
`docs/unwired-audit.md` records the others.

Neither of the two obvious checks can see it. Unit tests import the package they test, so they pass
whether or not anything else imports it. `go build ./...` happily compiles a library nothing links.
The gap is invisible to exactly the tools that look most like they would find it.

## What changes

Two artifacts, deliberately different in cost and in what they prove.

1. **`scripts/coverage-integration.sh`** — a reproducible measurement. It builds the `cmd/`
   binaries with `-cover -coverpkg=./...`, points the suite at them through the harness's existing
   `OPENSHIELD_INTEGRATION_BIN_DIR` seam with `GOCOVERDIR` set, and reports per-package statement
   coverage lowest-first plus the set of packages no shipped binary can reach. Not in any gate — it
   is a ~30-minute run — but a command anyone can re-run instead of a number in a document.

2. **`scripts/check-cmd-closure.sh`** — a fast guard, in `make quick`, `make check`, and CI. Every
   package must be reachable from `./cmd/...` or carry a recorded reason for not being. It runs in
   about two seconds, so it can gate.

The guard's allowlist is the substance of it. Nine packages sit outside the closure today and each
gets a reason naming its category — test-only CI guard, doc-only parent package, spike, or
platform-gated behind a `!linux` tag. The point is that the next entry has to be argued for.

## Impact

- No behaviour change. No new dependency, no proto change, no migration. Two scripts, three wire-ups
  (`make quick`, `make check`, the CI `invariants` job), and documentation.
- `make quick` grows by ~2s.
- Affected capability: **e2e-verification** — it gains requirements for the closure invariant and
  for the coverage measurement being reproducible rather than anecdotal.

## Honest limits, stated because a coverage number invites over-reading

- **Statement coverage is not path coverage.** Every line of a function can execute without its
  error branch ever being taken. A high number here does not mean the failure modes are exercised;
  it means the happy path is.
- **The measurement is of the integration suite alone**, deliberately. Unit tests cover far more.
  The whole value is in finding what *only* unit tests hold up.
- **Instrumentation changes timing.** Tests that pass in CI can fail under `-cover`. A failure in
  the instrumented run is a reason to look, not evidence of a product bug — and this proposal does
  not get to assume which, so any failure is reported as observed rather than explained away.
- **The closure is computed for one GOOS.** A package wired only behind a `!linux` tag looks
  unreachable on Linux. That is why those allowlist entries must name the importing file.
- **A guard against unwired packages is not a guard against unwired *features*.** A package can be
  imported by a binary and still be unreachable at runtime because no configuration turns it on.
  This check raises the floor; it does not close the class.
