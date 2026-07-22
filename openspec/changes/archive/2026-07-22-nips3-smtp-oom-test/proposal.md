## Why

The SMTP OOM guard's test proves nothing. `TestSMTPNoNewlineIsBounded` streams 64 KiB against the
32 MiB size ceiling, so the `io.LimitReader` never triggers — the session ends only because the idle
deadline fires. Removing the `io.LimitReader` (the actual anti-OOM guard) still ships green. It is the
signature "verifies against its own assumptions" pattern: the test exercises the deadline, not the
size ceiling it claims to defend. And a no-newline stream is bounded ONLY by the `LimitReader` — the
`total > maxBody` check accumulates on completed lines, which a newline-less flood never produces.

## What Changes

- Export the per-session byte ceiling as `Listener.MaxBody` (mirroring `MaxConns`/`IdleTimeout`:
  tunable before `Serve`, defaults to 32 MiB when non-positive, never disablable), so a test can set
  an aggressive small ceiling and drive the `LimitReader` directly.
- Rewrite the test to set a small `MaxBody` + a large `IdleTimeout`, stream past the ceiling with no
  newline and no stall, and assert the session is bounded and dropped **before** the idle timeout
  could fire — so removing the `LimitReader` now fails the test.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `smtp-connector`: the per-session byte ceiling is independently configurable, and the no-newline
  bound is enforced by that size ceiling on its own (provable without the idle timeout firing).

## Impact

- **Code:** `internal/connectors/smtp/listen.go` (`maxBody` → exported `MaxBody` + default fallback in
  `handle`); `internal/connectors/smtp/harden_test.go` (real size-ceiling test). The guard itself is
  unchanged — this is a false-premise-test fix plus the small surface needed to test it.
- **No proto/core change.**
