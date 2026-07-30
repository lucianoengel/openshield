# Design

## Nothing new — the mechanism already existed and the gate was not on it

`reportDiscards` (D348) already has exactly the right semantics: poll the counters, report only when one has
moved, and include every non-zero counter so the line reads as a state rather than a delta. Its comment
already argues why a periodic unconditional line becomes noise and then silence.

The whole finding is that the gate was not wired to it. That is the same shape as the unwired-feature audit:
a mechanism that exists, is correct, is tested, and does not cover the thing that most needs it.

## Why the gate is the case that mattered most

The listeners discard INPUT — messages that never entered the pipeline. The gate discards two other things:

- a full classification, so the file was seen only through its bounded prefix; and
- an **audit row for a decision that was already made and acted on**.

The second is evidentiary. D358 exists because a gate decision with no record is a decision nobody can
review, and the drop path recreates exactly that under load. It was counted, which is right — and reported
at a moment that never arrives on a busy endpoint.

## Making the overflow reachable

The queue depth was a literal 256. Filling it in a test would mean 256 concurrent gated opens racing a
drain, which is slow and flaky. Configurable, the test sets it to one and the overflow is deterministic.

This is worth having beyond the test: a fileserver and a laptop do not want the same depth, and a bound that
cannot be tuned is a bound someone eventually removes.

## What the mutation proves

Reverting to shutdown-only reporting fails the scenario after its full 60s deadline — the engine is under
load, discarding, and saying nothing. That is the defect stated as a test.
