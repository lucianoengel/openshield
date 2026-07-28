# Design

## Refuse to PROJECT, not refuse to STORE

Two silences are available and only one is acceptable.

Dropping the telemetry entirely keeps `unified_alerts` clean and destroys the evidence that a
malformed decision arrived — which is itself the interesting signal, and the thing an investigator
would want after discovering an agent was compromised.

Projecting it keeps the evidence and corrupts the stream that correlation, incidents and entity risk
are built on, where a forged CRITICAL is indistinguishable from a real one.

So: stored as telemetry, not projected, counted, and logged. The raw payload survives for
investigation; nothing downstream reasons about it as if it were a decision this platform would make.

## Validated at the projection seam

`projectDecisionAlert` is where a decision stops being an opaque payload and starts being something
the platform reasons about. Validating earlier — at ingest — would mean deciding what to do with a
telemetry row that failed, and the answer is "store it anyway", so the check would not change the
outcome there. Validating later would mean the alert already exists.

## hasConfidence

`ValidateDecision` takes a `hasConfidence` flag because proto3 cannot distinguish an absent double
from `0.0`, and "the producer did not set confidence" and "the producer is certain this is benign"
are different claims. On this path the flag is derived from the wire form, so a decision that omits
confidence is refused rather than read as zero — which would otherwise sail through the range check
and be graded LOW.

## Counted, and therefore visible

`DecisionContractViolations` is an ordinary counter on the Server, so D348's guard requires it to be
rendered on `/metrics` — a counter added here without exposure now fails the build. That is the point
of having built the guard first.

The log line names which check failed and which agent sent it, because "a decision was refused" is not
actionable and "agent X is sending actions this build does not know" is.

## What the test has to prove

Not that `ValidateDecision` works — it has unit tests. That **the projection path calls it**, which is
what was missing. So the assertions are on `unified_alerts`:

- a decision with `confidence: 999` produces **no** alert, and specifically no CRITICAL one;
- a decision with an action outside the closed set produces no alert;
- a well-formed decision still produces one, because otherwise all of the above is satisfied by a
  projection that has stopped working.
