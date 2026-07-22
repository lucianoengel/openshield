## 1. Make the size ceiling tunable

- [x] 1.1 Rename `Listener.maxBody` → exported `MaxBody int64`; in `handle` read a local
      `maxBody := l.MaxBody` with a fallback to `maxMessage` when non-positive (mirror `IdleTimeout`).
      Use the local in both the `io.LimitReader(conn, maxBody+1)` and the `total > maxBody` check.
      Keep the constructor setting `MaxBody: maxMessage`; update the struct doc to note it is tunable.

## 2. Make the test real

- [x] 2.1 Rewrite `TestSMTPNoNewlineIsBounded`: set a small `MaxBody` (e.g. 4 KiB) + a large
      `IdleTimeout` (e.g. 30 s); stream more than `MaxBody` bytes with NO newline in a tight loop (no
      stall); assert `Dropped() > 0` quickly (well inside the idle timeout) — the size ceiling, not the
      deadline, ended it.
- [x] 2.2 Mutation guard (apply, FAIL, revert): remove the `io.LimitReader` → the no-newline flood is no
      longer size-bounded and the drop does not occur within the window → the test FAILs. Record it. (Confirmed 2026-07-22: an effectively-unbounded LimitReader → Dropped stays 0 for 2s under the 30s idle → FAIL; reverted.)

## 3. Gate + record

- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 3.2 decisions.md entry (next D-number); note it's a false-premise-test fix (guard unchanged).
- [x] 3.3 Roadmap + memory updated.
