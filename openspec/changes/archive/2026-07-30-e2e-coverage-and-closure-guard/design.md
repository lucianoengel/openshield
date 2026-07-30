# Design

## The measurement: why coverage of real binaries, not `go test -cover`

`go test -cover ./...` answers a different question. It reports what a package's *own tests* execute.
The question here is what runs when `openshield-engine` is started as a real process by the
integration harness, against a real Postgres and a real NATS, and driven end to end. A package can
sit at 90% unit coverage and be linked into nothing.

Go's `-cover` on a *binary* (not a test binary) is the mechanism:

- `go build -cover -coverpkg=./...` instruments every module package into each `cmd/` binary.
- Each instrumented process writes a coverage profile into `$GOCOVERDIR` **when it exits normally**.
- `go tool covdata` merges the profiles across all processes and all tests.

Three properties of the existing harness make this work without touching test code:

1. `OPENSHIELD_INTEGRATION_BIN_DIR` — `test/integration/harness.go:Binary` uses pre-built binaries
   from that directory instead of building its own. That is the injection point for instrumented
   builds.
2. `cmd.Env = append(os.Environ(), env...)` — children inherit `GOCOVERDIR` from the test process.
3. **The harness stops processes with SIGTERM before SIGKILL.** This is the load-bearing one. A
   SIGKILLed process flushes no profile, so a harness that killed outright would silently measure
   nothing. It does not, so this works — but the dependency is worth recording, because a future
   "just kill it, it's a test" simplification would quietly break the measurement rather than fail.

### A build detail that silently produces nothing

`go build -cover -o <dir> ./cmd/...` writes into `<dir>` because the target is multiple main
packages and `-o` names a directory. `go build ./...` with several main packages **discards** the
output entirely. Getting this wrong yields an empty bin directory and a harness that fails with
"binary not found", which is at least loud — but the adjacent mistake (building into the current
directory) silently pollutes the tree, which is what `scripts/check-no-binaries.sh` exists for.

### The parse is a hazard, and it already lied once

`go tool covdata percent` prints `<pkg>\tcoverage: 26.3% of statements`. An ad-hoc version of this
analysis parsed `$NF` — which is the word **"statements"** — so every numeric filter matched nothing
and the report came back empty. An empty work list reads exactly like "everything is covered". The
script therefore parses field 3 **and refuses to report** when the parse yields zero rows from a
non-empty profile set, because a silent empty result is the worse failure (D31: a gap must never be
silent).

Same discipline for the profiles themselves: zero profiles collected is an error, not a report of
0%. The distinction between "nothing ran" and "the measurement did not happen" is exactly the one a
number cannot express on its own.

## The guard: the import closure of `./cmd/...`

```
go list ./...            → every package in the module
go list -deps ./cmd/...  → everything transitively reachable from a shipped binary
comm -23                 → the difference: packages no binary can reach
```

This is a stronger statement than "0% covered". Zero coverage might mean the suite does not drive
that feature yet. Outside the closure means the code **cannot execute in any deployment however
configured** — there is no environment variable, no policy, no flag that reaches it.

### The allowlist is the design, not a workaround

Nine packages are legitimately outside the closure, in four categories:

| Category | Packages | Why it is correct |
| --- | --- | --- |
| test-only | `internal/doccheck`, `internal/fitness`, `internal/packaging` | CI guards. `internal/packaging` has *no implementation file at all* — only a guard test. |
| doc-only | `internal/agent`, `internal/connectors`, `internal/enforcers` | `doc.go` describing a family; the implementations are in subpackages. |
| spike | `spikes/t002-gc-pause`, `spikes/t005-fanotify` | Kept as the record behind D19 and T-005. Deleting them would delete the evidence for a decision. |
| platform-gated | `internal/connectors/filewatch` | Imported by `cmd/openshield-engine/watcher_other.go`, which is `!linux`-tagged and therefore invisible to `go list -deps` on Linux. |

Requiring a reason per entry is the whole mechanism. A bare allowlist would accumulate entries and
stop being read; the next unwired feature would hide among nine unexplained lines.

### The staleness half matters as much as the failure half

The script fails in **both** directions: an unexplained package outside the closure, and an
allowlist entry that is no longer outside it. Without the second, an entry that becomes wired stays
listed forever, the list grows past the point anyone reads it, and it becomes the hiding place it was
meant to prevent.

Both directions are mutation-verified rather than asserted: a throwaway unimported package must make
the guard fail, and a typo'd allowlist entry must make it fail as *stale* — and note that mutation
tripped both branches at once, which is the correct behaviour and worth having seen rather than
assumed.

## The platform caveat, recorded as a finding rather than hidden in a comment

`internal/connectors/filewatch` is the portable stdlib-polling file connector — the analogue of the
Linux fanotify connector, and **the only observation surface a Windows or macOS deployment would
have**. It is genuinely wired, behind `!linux`.

And the CI matrix runs `go build` + `go vet` on `windows-latest` with **no tests at all** (the step
is `if: runner.os != 'Windows'`, with a recorded and reasonable rationale — the behavioural suite is
POSIX by nature and Windows is out of Phase 1). macOS does run the unit suite, so `filewatch`'s own
tests execute there; nothing runs the *engine* on either platform.

So: the one code path a non-Linux deployment depends on has its behaviour proven exclusively on
Linux. That is defensible while Windows is out of scope, and it stops being defensible the moment
Windows enters scope. Recorded in `docs/enterprise-gap-assessment.md` as part of the platform gap,
not silently fixed here — making Windows a tested platform is a scope decision, not a script.

## Why the coverage script is not in any gate

It takes ~30 minutes and the number is not a pass/fail property. A coverage *floor* in CI was
considered and rejected: the floor either sits below the current number (proving nothing) or at it
(making any refactor that adds an untested branch a build failure, which trains people to game the
metric). The measurement's value is in the work list it produces, which a human reads. The closure
check is the part that is a genuine invariant, so it is the part that gates.
