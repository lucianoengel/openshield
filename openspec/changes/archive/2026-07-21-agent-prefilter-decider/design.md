## Context

D94's PreFilter needs a PartialDecider to actually classify within the permission window.
The engine and gateway already classify content in the worker + decide via OPA; the
decider is that machinery, bounded to a prefix and stripped of the audit write.

## Goals / Non-Goals

**Goals:** a concrete PartialDecider — bounded prefix → worker classify → policy →
Decision, no audit — proven with a real worker.

**Non-Goals:** the permission syscall (D52); reading the fanotify fd (production plumbing);
a new verb.

## Decisions

**Reuse the engine/gateway classify+policy shape, minus the ledger.** The decider builds a
per-event dispatcher with a prefix-classify stage + the policy stage and NO OnOutcome — the
synchronous tier never writes the ledger; the async engine owns the durable audit row (D16).
It returns the Decision to the prefilter only.

**Double-bounded read.** A read `LimitReader` caps how many bytes are read and shipped
across the IPC in the permission window (a latency/memory guard against a huge file), and
the worker's own `MaxBytes` caps the parse. Detection is bounded by whichever is smaller;
the two are defense in depth. The read bound is a latency/memory guard, not
detection-observable (the worker bound alone would also stop a past-prefix hit) — kept
deliberately, and the test proves the EFFECTIVE bound (a CPF past the prefix is not seen).

**The decider may hold bytes; only the worker parses them (D13).** It runs in the
unprivileged engine, not the privileged agent. Reading a raw prefix is not parsing; the
parse (the RCE surface) happens behind the worker's seccomp sandbox (D72).

## Risks / Trade-offs

- **A front-loaded prefix can miss a deep hit.** By construction — the async full-file tier
  catches and contains it. The two-tier trade-off, proven, not hidden.
- **Still no real syscall here.** The decider is proven behind the watchdog seam with a
  live worker; the FAN_OPEN_PERM adapter is external-gated (D52).
