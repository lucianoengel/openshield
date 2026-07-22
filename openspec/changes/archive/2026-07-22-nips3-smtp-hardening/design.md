# Design — SMTP listener hardening

## Two bounds, complementary

A no-newline attack has two shapes: a client that keeps STREAMING bytes with no delimiter, and one
that STALLS. Each needs its own bound. `io.LimitReader(conn, maxBody+1)` caps the total bytes the
session can make us buffer, so a continuous no-newline flood hits EOF at the ceiling rather than
growing `ReadString`'s buffer to OOM. The per-line idle deadline caps a stalled connection, so a
slowloris client that dribbles is dropped. Together they bound per-connection memory AND time.

## Refuse, don't queue

The accept semaphore caps concurrent sessions. When full, a new connection is CLOSED and counted
(`Refused()`), not queued — queuing under a flood just moves the unboundedness. With the per-conn
memory bound (maxBody) and the concurrency cap (MaxConns), total memory is bounded to
MaxConns × maxBody regardless of attacker behavior.

## Testable bounds

`MaxConns` and `IdleTimeout` are exported so a test can set aggressive values: an idle connection is
proven to be closed within ~IdleTimeout; opening more than `MaxConns` connections is proven to
refuse the excess (`Refused() > 0`). Both guards are mutation-tested — removing the deadline lets an
idle connection hang (the idle test fails), and removing the semaphore lets all connections through
(the cap test's `Refused()` stays 0). The no-newline bound is exercised by a burst-then-idle session
that is dropped within the timeout.
