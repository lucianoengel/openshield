# Correct an unreproducible claim in an archived design note

## Why

`2026-08-06-harness-per-test-databases/design.md` records, as fact:

> `go test ./internal/controlplane/ ./internal/xdr/` fails … each of these packages' `requireDB` fixtures
> DROPs a shared table list … One package therefore drops tables the other is using.

**I could not reproduce it, and the stated mechanism is wrong.**

- The same command now passes: `ok internal/controlplane 169.4s`, `ok internal/xdr 4.8s`.
- All three database-backed packages already take the **same process-wide advisory lock (920431)** on a
  dedicated connection held for the binary's lifetime — `internal/controlplane`, `internal/xdr` and
  `internal/store/postgres`. That serializes exactly the DROP-and-migrate window I claimed was racing.

The observed failure was real — one run of that command did fail — but its cause is **unknown**, and the
explanation I attached to it does not survive checking.

## What Changes

- The archived design note is corrected in place, with the correction visible rather than the claim
  silently deleted.
- No code changes. The `-p 1` advice is withdrawn as unfounded.

## Impact

- Affected specs: none. The claim lived in a design note, not in a requirement — which is why this is a
  correction rather than a spec repair.

## Why this gets a change at all

A wrong explanation in the spec store is worse than no explanation: the next person reads a hazard that
does not exist, and either works around it or spends time chasing it. Recording *"claimed, could not
reproduce"* is more useful than either a silent edit or leaving it standing.

It is also the failure mode this project explicitly guards against elsewhere — inventing a requirement to
match observed behaviour is how a spec stops being a specification.
