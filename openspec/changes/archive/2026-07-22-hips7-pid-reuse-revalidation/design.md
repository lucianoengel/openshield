## Context

`KILL_PROCESS` flows: the execaudit source builds a `ProcessSubject{pid,…}`; the engine's
`enforceTarget` returns the pid string; `KillEnforcer.EnforceTarget` parses it and calls
`platformKill(pid)`, which does `PidfdOpen(pid)` + `PidfdSendSignal`. `PidfdOpen(pid)` resolves the
pid to *whatever process currently holds it*. So a pidfd opened at kill time gives no protection
against reuse — only a pidfd (or start-time) captured while the ORIGINAL process was alive does. The
event carries no such captured identity. `(pid, start-time)` is effectively a unique process identity
and is serializable; a raw pidfd is not (the source and enforcer are decoupled by the event).

## Goals / Non-Goals

**Goals:**
- Capture a stable process identity (start-time) at observation, carry it on the event, revalidate at
  kill so a recycled pid is spared.
- A deterministic test of the revalidation (no reliance on actually recycling a pid).

**Non-Goals:**
- Eliminating the microscopic TOCTOU between the start-time re-check and the signal (bounded and far
  better than today; noted).
- Carrying a live pidfd across the event boundary (not serializable; start-time is the identity).
- Changing the critical-process guard (HIPS-8, already landed) or any frozen-core interface.

## Decisions

### D-a · Identity = process start-time (clock ticks), carried on the event
Add `uint64 start_ticks = 6` to `ProcessSubject`: field 22 of `/proc/<pid>/stat` (starttime, in clock
ticks since boot). Together with the pid it identifies the specific process instance; a recycled pid
gets a different start-time. Additive proto field, regenerated with the committed toolchain.

*Alternative considered:* a pidfd captured at observation, held until the kill. **Rejected** — an fd
is not serializable onto the event, and holding an fd per observed process leaks descriptors; the
start-time is a plain integer that rides the event.

### D-b · Capture in the exec source, best-effort, injectable
The source sets `start_ticks` after `ToEvent`, via an injectable `startTicks(pid) uint64` (default:
read `/proc/<pid>/stat`, Linux-tagged; `0` on any failure). `ToEvent` stays a pure record→event
function. If the process already exited by the time the record is processed, `start_ticks` is `0` and
the target is a bare pid — best-effort, and honest: no false claim of revalidation when none is
possible.

### D-c · Target encodes `pid:start_ticks`; the enforcer parses and revalidates
`enforceTarget` returns `"pid:start_ticks"` when `start_ticks > 0`, else `"pid"` (back-compat). The
`KillEnforcer` parses `pid[:start_ticks]` and passes both to the `kill` seam
(`func(pid int, startTicks uint64) error`). This keeps the `TargetedEnforcer` interface (a single
`target string`) unchanged — the identity rides inside the string, like a flow_id does.

### D-d · Revalidate in platformKill
`platformKill(pid, startTicks)`: if `startTicks == 0`, keep today's best-effort behavior
(`PidfdOpen`+send). Otherwise re-read the current pid's start-time; if it differs, the pid was recycled
→ **no-op** (spare the new holder); if it matches, `PidfdOpen`+`PidfdSendSignal`. The re-check-then-fd
window is sub-microsecond and strictly safer than the unconditional kill today; `PidfdSendSignal` on a
since-exited process still returns ESRCH (no-op).

### D-e · Deterministic test via a start-time mismatch
Recycling a pid on demand is impractical, but a **mismatched captured start-time is exactly what a
recycled pid looks like** to the enforcer. Spawn a real process; with its CORRECT start-time,
`platformKill` terminates it; with a DELIBERATELY WRONG start-time, `platformKill` spares it (the
live process keeps running). The enforcer-level parse/dispatch is unit-tested via the injectable seam.

## Risks / Trade-offs

- **Residual TOCTOU** (start-time re-check → fd open) → sub-microsecond; the consequence requires the
  original to exit, the pid to be recycled, and a start-time collision within that window — negligible,
  and strictly better than the current no-check kill. Documented.
- **`start_ticks == 0` events are not reuse-protected** → only when the process exited before capture;
  the target degrades to a bare pid honestly rather than pretending to revalidate.
- **Proto field addition** → additive, regenerated and `proto-check`-verified; no reader breaks on an
  absent field (defaults to 0 = "unknown", the back-compat path).

## Migration Plan

Additive and drop-in: old events without `start_ticks` decode to 0 → bare-pid targeting (today's
behavior). Regenerate the proto, no data migration. Rollback is reverting the commit.

## Open Questions

None.
