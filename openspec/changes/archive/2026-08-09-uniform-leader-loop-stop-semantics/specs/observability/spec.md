## ADDED Requirements

### Requirement: A scheduled leader loop's own stop MUST NOT be counted as a failure

Every scheduled loop that runs under the leader lease and maintains a failure counter SHALL apply the
same exemption: an error returned by a tick SHALL NOT increment that loop's failure counter when, and
only when, BOTH the loop's own context has been cancelled AND the error IS that cancellation. Every
other error SHALL be counted exactly as before. This SHALL hold identically for correlation, beaconing,
playbook execution, escalation sweeps, approval expiry, ITSM sync and the retention sweep, so the
counters are comparable to each other.

The loops run in the leader's context, so losing leadership or shutting the process down cancels them out
from under whatever query or request is in flight, and that call returns "context canceled". Counting it
means an ordinary demotion or restart raises a counter whose published meaning is that detection,
orchestration, escalation, ticketing or retention is broken — and an alarm that fires on a routine event
is one an operator learns to ignore, which costs exactly the signal it carries.

UNIFORMITY IS ITSELF THE REQUIREMENT, not a tidiness preference. These counters are rendered side by side
on one metrics surface. One loop exempting its stop while its siblings count theirs means the family
carries two different meanings with nothing distinguishing them, and an operator comparing them during an
incident reads the difference as signal about the estate when it is an artefact of the code.

THE RULE IS KEYED ON THE LOOP'S OWN CONTEXT, AND THE CONTEXT ALONE IS NOT SUFFICIENT. The leader cancels
its own context when its database ping fails, so an outage produces a genuine driver error and a
cancelled context in the same window; exempting on the context alone discards the very failure the
counter exists to report. Requiring the error to BE the cancellation keeps schema skew, deadlocks, pool
exhaustion, a malformed operator-authored input and an aborted outbound request counted. Equally, the
error alone is NOT sufficient: a cancellation arriving while the loop's context is still live belongs to
somebody else's cancelled work and remains a real fault. The predicate SHALL therefore be evaluated
against the context the loop was started with, never against the per-tick context handed to the work
function — those are the same value today, and a guard that reads the wrong one is wrong the moment they
diverge.

THE EXEMPTION IS ABOUT NOT PAGING, NOT ABOUT THE WORK BEING SAFE. Interrupted work is generally
re-attempted, because the leader re-acquires after a demotion and starts the loops again in the same
process. Where an interrupted tick can leave a side effect OUTSIDE this system that the re-attempt does
not reconcile, the loop SHALL record which phase was interrupted, so the exemption never disguises an
unreconciled remote state as a routine stop.

THE OBLIGATION IS UNIVERSAL; THE BUILD-TIME CHECK IS NOT. The guard below sees a counter incremented
inside a loop's work function. An increment in a method CALLED FROM that function is equally bound by this
requirement but is invisible to a lexical check, so it remains a review question rather than a build
failure. A loop's transitive writes are part of its stop behaviour and SHALL be brought through the helper
when found; nothing here claims the guard finds them all.

TWO OF THESE COUNTERS ALSO COUNT SOMETHING THAT IS NOT A TICK. `CorrelationFailures` and
`EscalationFailures` are additionally incremented when an operator-authored hunts file or escalation
ladder fails to parse, from the configuration providers rather than from a tick. Those increments are
correct and SHALL be left alone — a file edited into an invalid state must not silently disable
detection — but they mean those two series are not purely "ticks that failed", and this requirement does
not claim otherwise.

#### Scenario: A stop mid-tick counts nothing, in every loop
- **WHEN** a loop's context is cancelled while its tick is in flight, for each leader loop that maintains
  a failure counter
- **THEN** that loop's failure counter is unchanged

#### Scenario: A real failure arriving while the loop stops is still counted, in every loop
- **WHEN** a tick fails with an error that is not the cancellation, and the loop's context is cancelled
- **THEN** it is counted, because a database outage produces both at once

#### Scenario: A cancellation on a live loop is still counted
- **WHEN** a tick returns a cancellation while the loop's own context has not been cancelled
- **THEN** it is counted, because that cancellation is somebody else's work being abandoned, not this
  loop stopping

#### Scenario: The predicate is asserted directly, not only through a loop
- **WHEN** the four combinations of live/cancelled context and cancellation/other error are evaluated
- **THEN** the shared predicate returns the exemption for exactly one of them
- **AND** widening it to the context alone, or narrowing it to the error alone, each fails the assertion

#### Scenario: A stop that left an unreconciled remote record says so
- **WHEN** a stop interrupts a loop after a third-party system has accepted a create and before the local
  link recording it was written
- **THEN** the recorded line distinguishes that case from a stop during an ordinary read-back, and states
  that a remote record exists with no local link — the fact a responder can act on

### Requirement: A tick that is not counted MUST still be logged, in the shipped process

Every failing tick of a scheduled leader loop SHALL be logged, whether or not it was counted, and the log
call SHALL NOT be conditional on the outcome of the counting decision. The line SHALL state whether the
loop was stopping, so a reader can tell an exempted tick from a counted one without inferring it from the
counter.

THIS SHALL HOLD IN THE SHIPPED BINARY, NOT MERELY IN THE FUNCTION SIGNATURE. A loop that accepts a logger
and is handed nothing logs nothing, and a requirement satisfied only by a parameter that production never
populates is a requirement that ships as a no-op. Therefore: a loop given no logger SHALL fall back to a
process-wide default rather than skipping the record, AND the commands that start these loops SHALL pass
a real logger. Both halves are required — the fallback alone would let every call site stay empty, and
the wiring alone would leave the next caller free to reintroduce the gap.

NOT COUNTING AND NOT RECORDING ARE SEPARATE DECISIONS, and conflating them is a defect this project has
already made once. Not counting is about not paging. The log is the only remaining trace that a tick was
abandoned, and an aborted tick that leaves nothing behind cannot be explained afterwards — D31: a gap must
never be silent. An earlier version of this guard put the log inside the counting branch, so a genuine
database outage arriving during a shutdown produced no count AND no line at all.

#### Scenario: An exempted tick still leaves a trace
- **WHEN** a tick is not counted because the loop is stopping
- **THEN** it is still logged, and the line says the loop was stopping

#### Scenario: A counted tick is logged too, and says it was not a stop
- **WHEN** a tick fails with a real error on a live loop
- **THEN** it is logged, the line says the loop was not stopping, and the counter moved

#### Scenario: A loop handed no logger still records
- **WHEN** a loop is started with no logger and a tick fails
- **THEN** the failure is still recorded through the process-wide default, rather than silently dropped

#### Scenario: No loop call site in the shipped command is handed an absent logger
- **WHEN** the control-plane command's loop startup is examined
- **THEN** no scheduled-loop call site passes an absent logger, and reintroducing one at any site fails
  the check naming that site

### Requirement: The stop rule MUST be structurally impossible to get wrong at a call site

The decision to count, the decision to log, and the stamping of whether the loop was stopping SHALL be
made in ONE shared helper that every scheduled loop calls, rather than repeated at each loop. The helper
SHALL take the loop's own context explicitly, so the call site names the context the exemption is keyed
on.

A guard SHALL fail the build when a failure counter is incremented directly inside a scheduled loop's
work function anywhere in the repository, since that is precisely the code path the helper exists to
own. The guard SHALL derive the set of loops from the source rather than from a maintained list, and
SHALL fail rather than pass when its scan finds nothing to check.

A rule applied by hand at every call site is applied at all but one of them within a year — this project
has the receipt, since the rule reached one loop of seven. Repetition also cannot be checked cheaply: a
guard that tries to verify a hand-written conditional has to reason about its polarity and about which
context it reads, and one that does not do both accepts `if stopping(err)` and `if !isLoopStop(c, err)`
as compliant, making the requirement above unfalsifiable at exactly the sites it was written for. Moving
the decision into one helper collapses the check to a lexical one — no counter increments inside a loop
body at all — which has no polarity to misread and no false positives.

#### Scenario: A new loop that counts its own failures directly
- **WHEN** a scheduled loop is added that increments a failure counter inside its work function
- **THEN** the guard fails and names the loop, directing it to the shared helper

#### Scenario: The rule is enforced beyond the package that prompted it
- **WHEN** a scheduled loop that counts failures is added in a command rather than in the control-plane
  package
- **THEN** the guard sees it and holds it to the same rule

#### Scenario: The guard cannot pass by finding nothing
- **WHEN** the guard's source scan yields no scheduled loops
- **THEN** it fails saying the check did not happen, rather than reporting success
