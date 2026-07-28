# The reproducibility claim has no way to be exercised

## Why

The roadmap states the project's thesis in one sentence: *every security decision — detection,
correlation, and response — is explainable, **reproducible**, and cryptographically auditable*. The
`policy-evaluation` spec says decisions are "deterministic and replayable", and the policy engine is
built for it: no network, no clock, no randomness.

`core.Replay` implements exactly that check — re-dispatch a recorded event and compare the resulting
Decision against the recorded one, on an explicit allowlist of fields chosen so that adding a new
field forces a deliberate decision about whether it should be compared. It is careful, documented,
unit-tested, and **has no caller**. No command exposes it. Nobody has ever replayed a decision.

So the auditable half of the thesis is real and independently verifiable — `openshieldctl verify`
proves the ledger was not edited — while the reproducible half is a property of the design that no
operator can demonstrate. "Deterministic and replayable" is currently a claim about the code, not
something a deployment can be asked to show.

This is the fifth instance of the shape this audit keeps finding, and the one that sits closest to
the product's central promise.

## What Changes

- `openshieldctl replay --event <file>` takes an Event the operator supplies, looks up the decision
  the ledger recorded for it, re-evaluates it through the policy, and reports whether the decision
  REPRODUCES or DIVERGES — naming the field that differs when it does.
- A divergence is a non-zero exit, because the interesting use is a script: "would this policy change
  still produce last quarter's decisions?" is a question worth failing a pipeline over.

## Impact

- Affected specs: `audit-timeline`
- Affected code: `cmd/openshieldctl`, `internal/cli`
- No proto change, no migration, no new dependency.
- Read-only. `openshieldctl` does not write to the ledger and does not start doing so here.

## The limit that shapes the whole command

**The ledger does not store the event, deliberately.** It is content-free (D10/D29) — that is the
privacy property the product is built around, and it is not being relaxed. So replay cannot be
"re-run decision 45"; the operator must supply the event, from wherever they still have it.

That makes the command answer a narrower question than it first appears to: *given this input, does
the policy still produce what was recorded?* It does NOT establish that the input was what the
original decision saw. A file event replays against the file's CURRENT content, so a divergence can
mean the policy changed, or the file did — and the command must say so rather than let an operator
read "DIVERGED" as proof of a policy regression.

Stating that limit is most of the value. A replay command that implied more would be worse than none.
