# Design — per-test databases

## Removing the coordination beats documenting it

The alternative fix was to rename one caller. That leaves the convention in place, and the convention is
the defect: every future test must know which names are taken, and the penalty for not knowing is a red
CI run rather than a local failure.

Scoping the name to `t.Name()` deletes the requirement to coordinate.

## Truncate from the tail

Postgres identifiers cap at 63 bytes. This suite's test names share long prefixes (`TestTheRealEngine…`),
so cutting from the front is precisely where two names would collide again. The caller's own label is
always kept, so a leaked database is still identifiable by what it was for.

## Why targeted runs cannot catch this class

The project rule is to run only the tests covering the change. A shared-resource conflict is invisible
under `-run` by construction, so this class will ALWAYS surface in CI rather than locally. That is an
argument for making the class impossible, not for running more tests — which is why the fix is structural
rather than a rename plus a note.

## Mutate each seam separately

The first mutation attempt broke `DSNFor` while the unit test exercised `scopedDBName`; it did not kill,
and the test was proving less than it appeared to. Breaking the naming fails the unit assertions; breaking
the wiring reproduces the CI error verbatim. Two seams, two mutations.

## A related hazard found while verifying this — CLAIM WITHDRAWN, see below

> **CORRECTED the same day (see `2026-08-06-correct-parallel-package-claim`). The observation below was
> real; the mechanism I attached to it was not, and I recorded it without reproducing it. The paragraph is
> kept rather than deleted so the record shows what was believed and why it did not hold.**

~~`go test ./internal/controlplane/ ./internal/xdr/` fails; `go test -p 1 …` passes. Go runs packages in
parallel by default, and each of these packages' `requireDB` fixtures DROPs a shared table list — including
`entities` and `entity_aliases` — on the same database. One package therefore drops tables the other is
using.~~

**What actually holds:**

- One run of that command did fail. That much is observed.
- The stated mechanism is wrong. All three database-backed packages — `internal/controlplane`,
  `internal/xdr` and `internal/store/postgres` — already acquire the **same process-wide advisory lock
  (920431)** on a dedicated connection held for the binary's lifetime. That serializes precisely the
  DROP-and-migrate window claimed to be racing.
- Re-running the same command passes: `ok internal/controlplane 169.4s`, `ok internal/xdr 4.8s`. A prior
  isolated run of `internal/controlplane` also passed.
- **The cause of the one failure is unknown.** A candidate, explicitly a hypothesis and not a finding:
  several long-running background test processes were active in that session, so two binaries for the
  SAME package may have overlapped.

The `-p 1` advice is **withdrawn** as unfounded.

**CI is not exposed either way:** `go test -race ./...` runs without Postgres, so every database-backed
test skips there.
