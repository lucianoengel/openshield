# Design — DLP-2 one job, one pipeline run

## Why the enqueue is the half to remove

Both producers had two paths to the pipeline and only one of them could be right.

`eng.Process` is not a lighter operation than the observation loop's — it *is* the observation loop's,
plus returning the decision. It classifies, decides, appends to the ledger, runs the enforcers and
projects telemetry. The channel send added a second run of all of that and one extra log line.

So the enqueue is pure duplication, and removing it is strictly less work with strictly more correct
behaviour. Removing the `Process` call instead was never an option: it is the verdict, and the
producers exist to return one.

## The parameter goes, not just the line

`printDecider` and `mediateClipboard` no longer take the `events` channel at all.

An unused parameter invites the line back — the send looks like an obvious omission next to a channel
sitting in the signature, and the reviewer who restores it gets a fail-open with no test failure,
because the defect only appears when a consumer is attached. Removing the parameter makes the mistake
unexpressible rather than merely absent.

## Why the tests could not see it

Both existing tests hand the decider a **buffered channel with no consumer**. That is precisely the
condition under which the bug cannot occur: nothing drains, so nothing races for the content, and the
verdict path always wins by default.

The production shape is a consumer draining the channel. The new test attaches one.

This is the second time this shape has appeared here — a test that passes because the component that
triggers the failure is the one the test omits.

## What is deterministic and what is not

Which of the two runs wins the race is not testable, and the reproduction that first showed the fail-
open ("a job containing a CPF was ALLOWED") could in principle have gone the other way on another run.

**How many runs there are** is deterministic, and it is the property that has to hold: one job, one
classification, one ledger entry. Both assertions fail under the mutation regardless of scheduling.

The hazard itself is stated separately and deterministically: run the pipeline twice over one event
id and the second decides ALLOW, because the store released the bytes on the first read. That test
does not depend on the fix at all — it documents why a duplicate run is unsafe, so the removal reads
as a fix for a known failure rather than as a tidy-up.

## The guard: a blind run must not be silent

Removing the enqueue fixes the two producers that had it. The root cause is more general: a second
consumer of one-shot content classifies nothing, and for a producer whose content arrives out-of-band
an empty classification is a *clean result*, not an error. Nothing in any log distinguishes it.

`ContentStore.Repeats` counts a resolve for an id whose content was already handed out. That is
precise in a way a miss counter would not be: the engine consults the resolver for every
non-filesystem event, so a DNS query legitimately misses, and counting misses would bury the signal.
A repeat is only ever a duplicate consumer.

The window is bounded by the same ceiling as pending registrations. It is a recent-history check, not
a log.

## Contradiction check

None. `ContentStore`'s documented properties — it CHAINS, and it RELEASES — are both unchanged, and
the release-on-read behaviour is deliberately kept: content must not linger in memory after
classification (D29). The fix removes the second consumer rather than weakening the release.
