## 1. Proto: carry the process start-time

- [x] 1.1 Add `uint64 start_ticks = 6;` to `ProcessSubject` in `proto/openshield/v1/event.proto`
      (comment: process start-time in clock ticks, captured at observation, for pid-reuse-safe kill).
- [x] 1.2 Regenerate (`make proto`) and confirm `make proto-check` is clean.

## 2. Capture at observation (execaudit)

- [x] 2.1 Add an injectable `startTicks func(pid int32) uint64` to the execaudit `Source` (default the
      real reader); in `emitIfComplete`, after `ToEvent`, set `ps.StartTicks = s.startTicks(ps.Pid)`
      on the process subject. `ToEvent` stays a pure record→event function.
- [x] 2.2 Linux `readStartTicks(pid)` reads field 22 of `/proc/<pid>/stat` (parse after the LAST `)`
      to survive a comm with spaces/parens); `0` on any error. Non-Linux stub returns `0`.

## 3. Encode the target + revalidate

- [x] 3.1 `engine.enforceTarget`: for a process event, return `"pid:start_ticks"` when `start_ticks>0`,
      else bare `"pid"`.
- [x] 3.2 `KillEnforcer.EnforceTarget`: parse `pid[:start_ticks]`; keep the pid≤1/self/critical guards on
      the pid; pass `(pid, startTicks)` to the `kill` seam (signature `func(pid int, startTicks uint64) error`).
- [x] 3.3 `platformKill(pid, startTicks)` (Linux): if `startTicks==0`, current best-effort (PidfdOpen+send);
      else re-read the current pid's start-time — mismatch → no-op (recycled, spare it); match → PidfdOpen +
      PidfdSendSignal. Update darwin/other kill signatures. Fix the stale "resists reuse" comment.

## 4. Verify + mutation guards

- [x] 4.1 Enforcer unit test (injected kill): a `"pid:ticks"` target parses and passes both through; a
      bare `"pid"` target passes `startTicks=0`; a non-numeric target errors; pid≤1/self still refused.
- [x] 4.2 Real-process test (Linux): spawn a `sleep`; capture its real start-ticks; `platformKill(pid,
      correctTicks)` terminates it; a fresh `sleep` with a DELIBERATELY WRONG start-ticks is SPARED
      (stays alive) — the deterministic stand-in for a recycled pid. A `startTicks=0` kill still terminates.
- [x] 4.3 `readStartTicks(self)` returns a non-zero value that is stable across two reads (sanity).
- [x] 4.4 Mutation guard (apply, FAIL, revert): drop the start-time revalidation in `platformKill` (kill
      regardless) → the wrong-ticks process is killed → the "spared" assertion FAILs. Record it. (Confirmed 2026-07-22: `false && cur != startTicks` → the wrong-ticks kill actually terminates the sleep → the background Wait observes the exit → "guard failed to spare" FAIL; reverted. Note: liveness must be checked via a background reap, not kill(pid,0) — a SIGKILL'd-but-unreaped zombie still answers kill(pid,0).)

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (incl. `proto-check`); `GOOS=windows/darwin go build ./...` clean.
- [x] 5.2 decisions.md entry (next D-number).
- [x] 5.3 Roadmap + memory updated.
