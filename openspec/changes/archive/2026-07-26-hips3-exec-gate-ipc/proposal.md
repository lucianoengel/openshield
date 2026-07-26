## Why

The inline exec gate works on a live kernel today, but it decides from a **static** parser-free
deny-list/whitelist held inside the privileged binary. It cannot consult the pipeline, so it cannot act on
anything dynamic — which is precisely what coordinated response requires: XDR-6's `CONTAIN(entity)` must
PREVENT the entity's next exec, not kill it after it has already run.

The bridge that would let it is designed and built but unwired: `internal/agent/execguard` holds
`Decider` (exec event → `engine.Process` → Action) and `ExecEvaluator` (DENY_EXEC → block, everything else
allows), and its only reference in the tree is a comment. What is missing is the transport between a
privileged process that must never parse anything and an unprivileged engine that holds the policy.

## What Changes

- **A new parser-free IPC package** (`internal/agent/execipc`) carrying exec verdicts between the two
  processes. Fixed-shape hand-rolled framing over a unix socket — magic, version, request id, pid, a
  length-capped path; a bounded response. Lengths are validated **before** allocation. It uses
  `encoding/binary`, `net`, `io`, `time`, `sync` and nothing else: no protobuf, no `corev1`, so the
  privileged binary's dependency budget does not move.
- **A CI assertion that the privileged binary still carries no protobuf/corev1**, alongside the existing
  parser ban. The ban exists because a parser bug at CAP_SYS_ADMIN is host compromise; the same argument
  applies to anything that decodes a wire format, and today's cleanliness should not depend on nobody
  adding an import.
- **The privileged side becomes a `watchdog.Evaluator`.** The watchdog already enforces a per-event budget
  and fails open loudly on both timeout and evaluator error, so the client's contract is narrow and
  absolute: **never block, and never guess.** A mismatched request id, a short frame, a bad magic or
  version, a closed socket — each is an error, which the watchdog turns into allow-plus-high-severity-audit.
- **Hardening the roadmap named, each with its own test:** a short-TTL verdict cache plus a per-path
  circuit breaker so a fork storm cannot amplify into an IPC storm; reconnect-and-continue when the engine
  restarts, with no stuck error state and no stuck EACCES; and a bounded in-flight limit that fails open
  immediately rather than queueing without limit.
- **An engine-side verdict server** that builds a process-exec event, runs the pipeline, and answers DENY
  iff the decision is `DENY_EXEC` — reusing `execguard`'s existing semantics rather than re-deriving them.
- **Both sides are env-gated and default OFF.** With no configuration the agent behaves exactly as it does
  today, and a missing or unreachable socket leaves it working in static mode rather than failing to start.

## Capabilities

### Modified Capabilities

- `inline-prevention`: the inline exec verdict can now come from the full pipeline over IPC, with the
  fail-open, fork-storm, restart and bounded-queue properties that a privileged inline gate requires; and
  the privileged binary's dependency ban extends to wire-format decoders.

## Impact

- **Code:** new `internal/agent/execipc` (client + server + framing); wiring in `cmd/openshield-agent`
  (env-gated evaluator) and `cmd/openshield-engine` (env-gated listener); one CI check extension. No
  change to `watchdog` (its budget and fail-open already do the work), none to `execguard`'s semantics,
  none to the frozen core, no proto change, no migration, no new dependency.
- **Decisions:** depends on **D13** (the privileged process never parses attacker-controlled bytes — the
  reason this transport is hand-rolled), **D17/D73** (fail-open is mandatory for stability and is itself
  audited), **D14** (the closed action set: only `DENY_EXEC` blocks), and **D10/D29** (only metadata
  crosses — a path and a pid, never content). It establishes no new decision.

### What this change does NOT claim or cover

- **This is increment 2a: the bridge, not intent-driven containment.** The roadmap's full acceptance for
  HIPS-3 increment 2 is *"a `CONTAIN(entity)` intent makes the entity's next exec kernel-REFUSED"*. That
  needs the signed Response-Intent as typed policy context, which is **SOAR-7 and is not built**. This
  ticket proves a **policy-driven** inline deny over the real kernel path; until SOAR-7 lands, nothing
  here should be described as intent-driven containment, and XDR-6 remains blocked on both.
- **Fail-open is the only supported mode, and it is a real trade-off.** An operator gets availability over
  enforcement: if the engine is dead, hung, or overwhelmed, execs run unchecked. That is deliberate — a
  dead engine must never brick a machine's ability to run programs — and the high-severity audit on every
  fail-open is what makes it detectable rather than silent. It is not a claim that the gate cannot be
  bypassed by an adversary who can stop the engine.
- It does **not** make the privileged binary parse anything, and it never will.
- It does **not** bring inline DLP on file-open (D49: classification cannot complete inside the permission
  window), eBPF/LSM hooks, a connection pool beyond one reconnecting socket, or Windows/macOS.
- The verdict cache means a repeated exec of the same path can be answered from a recent verdict rather
  than a fresh policy evaluation. That is a deliberate fork-storm defense with a short TTL, not a claim of
  per-exec freshness.
