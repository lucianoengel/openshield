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

## A related hazard found while verifying this, and deliberately NOT fixed here

`go test ./internal/controlplane/ ./internal/xdr/` fails; `go test -p 1 …` passes. Go runs packages in
parallel by default, and each of these packages' `requireDB` fixtures DROPs a shared table list — including
`entities` and `entity_aliases` — on the same database. One package therefore drops tables the other is
using.

**CI is not exposed:** `go test -race ./...` runs without Postgres, so every database-backed test skips
there. The hazard is local, for anyone running the DB suite across packages — which is exactly how this
project verifies persistence.

It is **not fixed in this change**, and the reason is scope rather than effort: this change is about
resources a scenario creates INSIDE the integration stack, and that is about package-level fixtures
sharing one database. Folding them together would make one change that is really two, and the second one
touches three fixtures.

Recorded so it is a decision rather than a silence. Until it is fixed, run database-backed packages with
`-p 1` when running more than one.
