## Why

The pid-reuse guard does nothing. `platformKill` opens the pidfd with `PidfdOpen(pid)` **at kill
time**, and the process event carries only `pid` — no identity captured at observation. If the
observed process exited and its pid was recycled between the decision and the kill, `PidfdOpen`
opens the **new** holder and `KILL_PROCESS` terminates it — exactly the wrong-process kill the code's
comment claims to prevent. The claim is asserted by no test that drives the real syscall path (the
"verifies against its own assumptions" pattern, at the design level this time). A pid alone is not a
stable process identity; the process **start-time** is.

## What Changes

- The exec producer captures the process **start-time** (from `/proc/<pid>/stat`, in clock ticks) at
  observation and carries it on the event (a new `ProcessSubject.start_ticks` field).
- The engine encodes the enforcement target for a process event as `pid:start_ticks` (falling back to
  bare `pid` when the start-time is unknown, e.g. the process already exited at capture — best-effort,
  no revalidation possible then).
- `platformKill` **revalidates**: at kill time it re-reads the current pid's start-time and terminates
  only if it matches the captured one; a mismatch means the pid was recycled, so it is a no-op (the new
  holder is spared), never a kill of the wrong process.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `event-contract`: a process-exec subject carries the process start-time, so a later enforcement can
  distinguish the observed process instance from a recycled pid.
- `execaudit-connector`: the exec producer captures the process start-time at observation and carries
  it on the event.
- `enforcement`: the kill enforcer revalidates the captured process identity (start-time) at kill time
  and does not terminate a pid whose current holder does not match — the pid-reuse resistance is real,
  not claimed.

## Impact

- **Code:** `proto/openshield/v1/event.proto` (+`start_ticks` on `ProcessSubject`, regenerated),
  `internal/connectors/execaudit` (capture start-time, injectable + Linux `/proc` reader),
  `internal/engine/engine.go` (encode `pid:start_ticks`), `internal/enforcers/process` (parse the
  target, revalidate in `platformKill`; the `kill` seam carries the start-time), and tests.
- **Additive proto change only** — the frozen core interfaces (Dispatcher/State/Stage/Registry/
  Enforcer/OnOutcome/ledger) and the D10/D29 content boundary are untouched; `start_ticks` is
  timing metadata, not content.
