## Context

`handle` bounds a session's buffered bytes with `bufio.NewReader(io.LimitReader(conn, l.maxBody+1))`,
so a no-newline stream returns EOF at the ceiling instead of growing `ReadString`'s buffer without
limit. `maxBody` is set from the 32 MiB `maxMessage` const and is unexported. The existing test writes
64 KiB (≪ 32 MiB) then stalls, so the session ends on the idle deadline — the `LimitReader` is never
reached, and deleting it keeps the test green. The `total > l.maxBody` check is a second bound but it
only advances on completed lines, so it does not bound a newline-less flood; the `LimitReader` is the
sole defense there.

## Goals / Non-Goals

**Goals:**
- Make the anti-OOM size ceiling testable at an aggressive small value.
- A test that fails if the `LimitReader` is removed, proving the size ceiling (not the idle deadline)
  bounds a no-newline flood.

**Non-Goals:**
- Changing the guard's behavior or the 32 MiB production default.
- Touching the slowloris (idle) or concurrency (MaxConns) guards, which already have real tests.

## Decisions

### D-a · Export `MaxBody`, default-when-non-positive
Rename `maxBody` → `MaxBody int64`, mirroring the existing `MaxConns`/`IdleTimeout` convention: a
caller may lower it before `Serve`, and `handle` falls back to `maxMessage` when it is non-positive —
so it can be tuned but never disabled to 0/unbounded. The constructor keeps setting it to `maxMessage`.

*Alternative considered:* a test-only setter or build-tagged hook. **Rejected** — the codebase already
exposes `MaxConns`/`IdleTimeout` as plain exported fields for exactly this; consistency wins.

### D-b · The test drives the ceiling, not the deadline
Set `MaxBody` small (a few KiB) and `IdleTimeout` large (seconds), then write more than `MaxBody` bytes
with no newline in a tight loop (no stall). The `LimitReader` returns EOF at the ceiling, `ReadString`
errors, the session ends and is counted — well before the large idle deadline could fire. Asserting the
drop happens quickly (within a fraction of the idle timeout) proves it was the size ceiling. Removing
the `LimitReader` leaves only the (large) idle deadline, so the drop does not happen in the window and
the test fails.

## Risks / Trade-offs

- **Exporting a field widens the API** → minimal and consistent with `MaxConns`/`IdleTimeout`; the
  default and the never-disablable fallback keep production safe.
- **Timing-based test** → the window (drop before idle timeout) is generous (a large idle timeout vs a
  sub-millisecond ceiling hit), so it is not flaky under `-race`.

## Open Questions

None.
