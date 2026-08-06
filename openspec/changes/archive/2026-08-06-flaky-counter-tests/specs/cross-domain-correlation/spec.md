# cross-domain-correlation

## ADDED Requirements

### Requirement: Stopping the correlation loop is not a correlation failure

An error a scheduled correlation tick returns SHALL NOT be counted as a correlation failure only when
BOTH the loop's own context has been cancelled AND the error IS that cancellation. Every other error
SHALL be counted, unchanged. An error SHALL be logged in either case.

The loop runs in the leader's context, so losing leadership or shutting the process down cancels it out
from under whatever materialization is in flight; that query returns "context canceled". Counting it
raises the failure counter whose published meaning is that incidents which should have been joined were
not — so an ordinary demotion or restart landing mid-tick reported broken detection, and an alarm that
fires on a routine event is one an operator learns to ignore.

BOTH CONDITIONS ARE REQUIRED. The leader cancels its own context when its database ping fails, so an
outage produces a genuine driver error and a cancelled context in the same window; exempting on the
context alone discards the very failure the counter exists to report. Requiring the error to BE the
cancellation keeps schema skew, deadlocks, pool exhaustion and a malformed operator-authored hunt
counted.

NOT COUNTING AND NOT RECORDING ARE SEPARATE DECISIONS. Not counting is about not paging; the log is the
only remaining trace that a tick was abandoned, and an aborted tick that leaves nothing behind cannot be
explained afterwards.

#### Scenario: A stop mid-tick counts nothing
- **WHEN** the loop's context is cancelled while a tick is materializing
- **THEN** the correlation-failure count is unchanged

#### Scenario: A real failure arriving while the loop stops is still counted
- **WHEN** a tick fails with an error that is not the cancellation, and the loop's context is cancelled
- **THEN** it is counted, because a database outage can cause both at once

#### Scenario: An abandoned tick still leaves a trace
- **WHEN** a tick is not counted because the loop is stopping
- **THEN** it is still logged
