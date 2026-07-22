# ENG-2: contain parser panics in the engine's in-process connectors

## Why

The engine's D35 confinement assumption was "content parsing happens in the sandboxed worker; the
engine holds no attacker-controlled parsing." That changed: the engine now opens listening sockets
(DNS, and — once wired — SMTP) and runs the exec source, so it parses attacker-influenced wire and
audit bytes IN-PROCESS. A panic in any of those parsers (or a sink) on one crafted input would take
down the entire engine — and with it observation of the whole fleet. The assumption must be
RE-DERIVED, not just noted: the engine's in-process parsers are metadata-only, and each must contain
a panic to the single input that caused it.

## What Changes

- **Panic recovery in each in-process parse loop**: the DNS receive loop, the exec-source scan loop,
  and the SMTP session handler each recover from a panic while handling one datagram/record/session,
  dropping and counting it and continuing — a crafted input can no longer crash the engine.
- **Panic recovery in the engine's per-event loop**: `processOne` recovers around `eng.Process`, so
  a panic in any stage on one event is contained to that event rather than crashing the loop.

## Impact

- Affected specs: `agent-process-boundary`
- Affected code: `internal/connectors/dns/listen.go`, `internal/connectors/execaudit/source.go`,
  `internal/connectors/smtp/listen.go`, `cmd/openshield-engine/main.go`.
- Not in scope (stated): moving metadata parsing behind a separate sandbox boundary (the parsers are
  metadata-only and panic-contained; a full boundary is a heavier bet); the shared listener-hardening
  CONTRACT (deadlines/caps/rate-limits) that dedups this recover across connectors (NIPS-7); content
  parsing, which stays in the sandboxed worker (D29/D35 unchanged).
