# Design — correcting the claim

## Correct in place, visibly

Two options: delete the paragraph, or annotate it. Deleting loses the fact that a run genuinely failed —
which is evidence, even without an explanation. Annotating keeps the observation and withdraws the
mechanism.

The archived change is the historical record of what was believed at the time. A record that says "this
was claimed and did not survive checking" is worth more than one that was quietly made correct.

## What the evidence actually supports

- One run of `go test ./internal/controlplane/ ./internal/xdr/` failed.
- A later isolated run of `internal/controlplane` passed.
- A later run of the same two-package command passed.
- All three DB packages hold advisory lock 920431 for their process lifetime, on a dedicated connection,
  which serializes their DROP-and-migrate.

That supports "one failure, cause unknown". It does not support "these packages race on shared tables".

## The lesson, which is mine

I diagnosed from a plausible mechanism instead of reproducing. The same session had already caught me
three times assuming rather than probing — `OPENSHIELD_QUEUE_DIR`, `posture-enroll --agent`, and the two
pseudonym derivations — and each time a single command settled it. This one I wrote down before running
that command.

A candidate cause worth noting for whoever sees it next: several long-running background test processes
were active earlier in that session, so two test binaries for the SAME package may have overlapped. That
is a hypothesis, explicitly not a finding.
