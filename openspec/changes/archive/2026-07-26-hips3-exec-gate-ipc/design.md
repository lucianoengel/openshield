## Context

Verified at `HEAD`:

- `cmd/openshield-agent` (privileged, CAP_SYS_ADMIN) has an unusually narrow dependency graph:
  `go list -deps` shows `golang.org/x/sys/unix` plus `internal/agent/{execmon,watchdog}` and stdlib — **no
  protobuf, no `corev1`, no `encoding/json`, not even `log/slog`** (its own docstring explains it uses
  `fmt` to stderr because `slog` pulls `encoding/json` via `JSONHandler`).
- `internal/agent/watchdog` already implements exactly the budget semantics this ticket needs:
  `Handle` runs the evaluator in a goroutine under a `context.WithTimeout(Budget)`, answers the kernel on
  whichever completes first, and `failOpen` **writes the allow FIRST and audits second** so a slow ledger
  cannot become a hung host. An evaluator ERROR is already treated as a fail-open, not a block.
- `internal/agent/execguard` has `Decider` (exec event → `engine.Process` → Action) and `ExecEvaluator`
  (`DENY_EXEC` → `VerdictBlock`, everything else allow). Built, unit-tested, referenced only by a comment.
- `internal/agent/ipc` is the existing privileged↔worker transport (4-byte length + protobuf). It is the
  right *shape* to imitate and the wrong *payload*: it imports protobuf, which the exec gate's privileged
  side must not.

So the missing piece is genuinely just a transport, plus the abuse-resistance an inline privileged gate
needs. The budget, the fail-open, the audit and the decision semantics all already exist.

## Goals / Non-Goals

**Goals:**

- An exec verdict from the pipeline, over a transport that adds no parser to the privileged process.
- Never block; never guess. Every transport failure becomes an audited allow.
- Survive fork storms and engine restarts.
- Default OFF, byte-identical behavior when unconfigured.

**Non-Goals:**

- Intent-driven containment (SOAR-7), inline file-open DLP (D49), eBPF/LSM, connection pooling, non-Linux.

## Decisions

### D-1: A hand-rolled fixed-shape protocol, not protobuf

Request: `magic(4) | version(1) | request_id(8) | pid(4) | path_len(2) | path`.
Response: `magic(4) | version(1) | request_id(8) | verdict(1)`.
`path_len` is bounded (≤ 4096, and the whole frame ≤ a small constant); the bound is checked **before**
allocating.

*Alternatives:*

- **Reuse `internal/agent/ipc` (length + protobuf).** Rejected: it would put protobuf's decoder into the
  process holding CAP_SYS_ADMIN. The parser ban exists because a memory bug there is host compromise
  (ClamAV CVE-2025-20260 is the precedent the repo cites), and a wire-format decoder is a parser. The
  existing worker IPC is acceptable there precisely because the *worker* holds it — not the agent.
- **JSON.** Rejected for the same reason, plus `encoding/json` is already explicitly banned.
- **A shared-memory ring.** Rejected as far more mechanism than a per-exec request/response needs, with
  much worse failure modes at exactly the moment things go wrong.

Fixed-width fields mean the privileged side's "parsing" is four `binary.BigEndian` reads and one bounded
copy. There is no self-describing structure to get wrong.

### D-2: The client is an `Evaluator`, and the watchdog keeps owning the budget

`execipc.Client.Evaluate(ctx, PermissionEvent) (Verdict, error)` — that is the whole integration surface.

This is the most important structural decision in the ticket: **do not build a second budget/fail-open
mechanism.** The watchdog's `Handle` already races evaluation against the budget and fails open on both
timeout and error, with the allow-before-audit ordering worked out. A transport that re-implemented any of
that would produce two timeout paths that can disagree — and the one that disagrees under load is the one
that wedges a host.

So the client's obligations reduce to: return promptly, and return an error rather than a wrong verdict.
Socket deadlines are set shorter than the budget so the transport cannot be what exhausts the window.

### D-3: Request-id matching is mandatory, and a mismatch is fatal to the request

Every request carries a monotonically increasing id; a response whose id differs from the pending one is an
error, not a verdict.

This is the failure mode worth the most paranoia. If the socket ever desynchronizes — a partial write, a
timed-out request whose late answer arrives while the next request is pending — a client that ignored ids
would answer execution A with execution B's verdict: silently wrong in both directions, blocking innocent
programs and admitting denied ones, with nothing in the audit trail to reveal it. On a mismatch the client
also **drops the connection**, because a desynchronized stream cannot be trusted to resynchronize itself.

### D-4: Fork-storm defense: cache + per-path breaker + bounded in-flight

Three cheap mechanisms, because a fork bomb is the normal way this surface fails:

1. **Verdict cache**, keyed by exec path, short TTL (~1s). A fork loop over one binary collapses to one
   evaluation. The honest cost — stated in the proposal — is that a verdict can be up to a TTL stale.
2. **Per-path circuit breaker.** After N consecutive failures for a path, fail open *without* attempting
   the call until a cooldown elapses. Without it, a dead engine turns every exec into a full
   connect-and-time-out cycle, and the fail-open path itself becomes the bottleneck.
3. **Bounded in-flight semaphore.** Overflow fails open immediately. An unbounded queue under a fork storm
   is a memory-exhaustion bug in a privileged process.

*Alternative considered:* rate-limit globally rather than per path. Rejected — a global limiter lets one
noisy binary starve evaluation for everything else, which is the shape of an evasion (fork-storm a benign
binary to get an evaluation-free window for a denied one). Per-path breakers keep the blast radius on the
path that is misbehaving.

### D-5: One reconnecting socket, no pool

The client holds at most one connection, dials lazily, and drops-and-redials on any error. An engine
restart therefore costs a fail-open or two and then recovers by itself.

A pool would add concurrency the protocol does not need (requests are serialized under a mutex with the
in-flight bound) and would multiply the desynchronization risk from D-3 by the pool size.

### D-6: Env-gated, default OFF, and never fatal at startup

`OPENSHIELD_EXEC_IPC_SOCKET` on the agent, a listener flag on the engine. Unset = today's static behavior,
unchanged. If the socket is absent or unreachable at startup, the agent logs and continues in static mode:
an enforcement *upgrade* that prevents the agent from starting would reduce protection to zero in exchange
for a feature, which is the wrong direction for a security agent.

## Risks / Trade-offs

- **Fail-open is a real bypass, by design.** Anyone who can stop the engine gets unchecked execs. This is
  the deliberate availability trade (D17/D73) and the reason every fail-open is audited at high severity —
  the honest claim is detection of the gap, not prevention through it. Stated in the proposal, not buried.
- **A stale cached verdict** can allow an exec that policy would now deny (up to the TTL). Chosen over an
  uncached gate that a fork storm can DoS; the TTL is short and the trade is documented.
- **The breaker widens the fail-open window** for a path that has been failing — deliberately. The
  alternative is spending the permission budget on a call already known to fail.
- **A hand-rolled protocol is code we own.** Mitigated by keeping it fixed-shape (no optional fields, no
  nesting), bounding before allocating, and testing every malformed-frame class rather than only the happy
  path.
- **The engine side runs a listener on a unix socket.** Filesystem permissions are the access control; the
  socket must be created with a restrictive mode, and the engine is unprivileged, so the blast radius of
  reaching it is "can ask for exec verdicts", not privilege.
- **The VM-gated kernel test cannot run in ordinary CI.** It skips without root, as the existing exec-perm
  and TPM tests do, and is run on the rooted VM — with the PASS pasted into the decision record, because a
  gated test nobody runs is decoration.

## Migration Plan

None: additive, env-gated, default off. No schema, proto or dependency change. Rollback is unsetting the
env var (or the previous binaries).

## Open Questions

- Should the cache key include more than the path (e.g. the binary's inode/mtime) so a replaced binary is
  re-evaluated inside the TTL? Probably yes eventually; for a ~1s TTL the added `stat` per exec is a worse
  trade than the staleness, so it is deferred and named.
- Should a repeated *deny* be cached as aggressively as a repeated allow? Currently symmetric; if a denied
  fork storm proves to need faster answers, caching denies longer than allows is the obvious asymmetry.
