# NIPS-3-SMTP: harden the SMTP listener before wiring it

## Why

The built-but-not-yet-wired SMTP listener has three resource-exhaustion bugs that must be closed
BEFORE it is exposed to real traffic (it will accept attacker-controlled connections):
- **No-newline OOM**: it reads with `ReadString('\n')` and checks the 32 MiB bound only AFTER a full
  line, so a stream with no newline makes the buffer grow unbounded.
- **Slowloris**: `handle` sets no read deadline — a client that opens a connection and dribbles (or
  sends nothing) holds a goroutine + connection indefinitely.
- **Unbounded goroutines**: `go l.handle(conn)` per accept with no cap — N connections spawn N
  handlers, and combined with slowloris that is an unbounded resource flood.

## What Changes

- **Bounded reader**: the session read is wrapped in `io.LimitReader(conn, maxBody+1)`, so an
  unterminated stream returns EOF at the ceiling instead of exhausting memory.
- **Per-line idle deadline** (`SetReadDeadline` before each read, default 30s, resets each line):
  a stalled client is dropped, not held. Tunable via `IdleTimeout`.
- **Accept semaphore** (`MaxConns`, default 128): a connection arriving while the cap is full is
  REFUSED (closed + counted via a new `Refused()` counter, D28), not queued.

This hardens the `smtp-connector` capability. No behavior change for a well-formed session.

## Impact

- Affected specs: `smtp-connector`
- Affected code: `internal/connectors/smtp/listen.go`.
- Not in scope (stated): a shared listener-hardening contract across syslog/DNS/SMTP (NIPS-7 — this
  fixes SMTP specifically, ahead of its wiring); per-source rate limiting / ledger-write sampling
  (NIPS-7); TLS/STARTTLS on the capture endpoint (deployment).
