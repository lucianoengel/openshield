# Design

## What is compared, and why the list is explicit

`core.DecisionsEquivalent` already owns this and needs no change. It compares action, confidence,
reason, policy id and policy version against an explicit allowlist, excluding `decision_id` and
`decided_at` because they legitimately differ per evaluation.

The allowlist is the right shape and the doc comment already says why: with a denylist, a newly added
field would be silently excluded and replay would quietly weaken. Nothing here should turn that into
a reflection-based comparison for convenience.

## Where the recorded decision comes from

`Reader.Entries` already returns entries carrying the full recorded `*corev1.Decision`, and the
timeline filter already narrows by event id. Replay reuses both rather than adding a query: a second
way to read the ledger would be a second thing to keep correct.

If the event id matches no entry, that is an ERROR and not a divergence. "The policy produced
something different" and "there is no record of this decision" call for different responses, and
collapsing them would let a typo in an event id read as a policy regression.

If it matches MORE than one entry, that is also an error rather than a silent first-match. An event
that produced two decisions is either a re-processed event or a bug, and either way the operator
needs to know before comparing against one of them arbitrarily.

## Which policy it replays against

The one the CLI is configured with — the same default-plus-packs composition the engine builds. Not
the policy id recorded on the entry: the recorded id names what evaluated it THEN, and the whole
point of the command is to ask what happens NOW. When they differ, the report says so, because a
divergence explained by "you are running a different policy" is not a regression and must not read
like one.

## Reporting

Three outcomes, distinct on purpose:

- **REPRODUCED** — every compared field matches.
- **DIVERGED** — a field differs; the report names it, and states that the input may have changed as
  well as the policy.
- **UNAVAILABLE** — no such entry, more than one, or the event could not be read.

Exit status differs for each, because the intended use is a pipeline gate on a policy change. A
divergence that exited zero would be a gate that never fails.

## The caution the report must carry

A file event replays against the file's CURRENT bytes, because that is what classification reads. So
DIVERGED has two explanations and the report gives both. An operator who reads it as proof of a
policy regression, and reverts a policy over a file someone edited, has been misled by a tool that
was technically correct — which is the failure mode this project treats as worse than an error.
