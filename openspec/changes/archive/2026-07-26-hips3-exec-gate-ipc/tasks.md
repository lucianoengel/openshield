## 1. The wire protocol

- [x] 1.1 New package `internal/agent/execipc`: fixed-shape request/response framing
  (`magic|version|request_id|pid|path_len|path` → `magic|version|request_id|verdict`), bounds checked
  BEFORE allocation, using only `encoding/binary`/`io`/`net`/`time`/`sync`.
- [x] 1.2 Unit-test the round trip and EVERY malformed class: bad magic, unknown version, truncated header,
  truncated body, `path_len` beyond the bound (asserting no large allocation is attempted), zero-length
  path, and a response for an unknown request id.
- [x] 1.3 Extend `scripts/check-agent-deps.sh` to also fail on protobuf/`corev1` in the privileged binary,
  and assert the extended check passes today — so a future import cannot silently widen the parser surface.

## 2. The privileged client

- [x] 2.1 `execipc.Client` implementing `watchdog.Evaluator`: lazy dial, one connection, serialized
  request/response under a mutex, socket deadlines shorter than the watchdog budget.
- [x] 2.2 Request-id matching: a response whose id differs from the pending request is an ERROR **and drops
  the connection** (a desynchronized stream cannot be trusted to resynchronize).
- [x] 2.3 Test cross-talk explicitly: a server that answers with the wrong id → `Evaluate` errors and no
  verdict is applied. **Mutation:** accept a mismatched id → this must FAIL.
- [x] 2.4 Verdict cache (path-keyed, short TTL) + per-path circuit breaker (N consecutive failures → fail
  open with NO IPC attempt until a cooldown) + bounded in-flight semaphore (overflow → immediate fail-open).
- [x] 2.5 Tests for each: a second exec inside the TTL makes no second call; N failures trip the breaker and
  the next call does not touch the socket; a cooldown re-arms it; overflow fails open. **Mutation:** remove
  the breaker → the fork-storm test must FAIL.
- [x] 2.6 Fail-open tests through the REAL watchdog (not a mock of it): a hung server → allow + a
  high-severity audit within the budget; a closed socket → allow + audit; a killed-then-restarted server →
  allow during the outage, normal evaluation after. **Mutation:** make the gate fail CLOSED on timeout →
  these must FAIL (fail-open is the load-bearing safety property here, not a bug).

## 3. The engine-side server

- [x] 3.1 `execipc.Server`: accept a framed request, build an `EVENT_KIND_PROCESS_EXEC` event, obtain the
  action through the existing `execguard` semantics, answer DENY iff `DENY_EXEC`. One connection handler per
  accepted socket, with read deadlines so a stuck client cannot pin a goroutine forever.
- [x] 3.2 Test the server against a real policy: a policy that denies a path → `verdict=deny`; one that
  allows → `verdict=allow`; a pipeline error → an error response the client turns into a fail-open.
- [x] 3.3 Create the socket with a restrictive mode and remove a stale socket file on bind, so a restart
  does not fail with "address already in use".

## 4. Wiring, default OFF

- [x] 4.1 `cmd/openshield-agent`: `OPENSHIELD_EXEC_IPC_SOCKET` selects the IPC evaluator; unset keeps
  today's static evaluator byte-identically; an absent/unreachable socket logs and continues in static mode
  rather than failing to start.
- [x] 4.2 `cmd/openshield-engine`: an env-gated exec-verdict listener, shut down with the process.
- [x] 4.3 Test the default-off path: with no env var the agent's evaluator is the static one (no socket is
  dialed), and the existing static exec tests still pass unchanged.

## 5. The real-kernel VM test

- [x] 5.1 A gated kernel test (root + `FAN_OPEN_EXEC_PERM`, skipped otherwise, in the style of
  `execmon_kernel_test.go`): privileged producer → watchdog → `execipc.Client` → in-process
  `execipc.Server` → real engine+policy. A POLICY-driven deny makes a real `exec` fail with EACCES; the
  same exec under an allowing policy runs. **Mutation:** ignore the IPC verdict and always allow → the deny
  half must FAIL.
- [x] 5.2 Build with `go test -c`, scp to the rooted VM, run under sudo, and paste the PASS into the
  decision record — a gated test nobody runs is decoration.

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green locally (the kernel test SKIPS without root, like
  the execmon/tproxy tests), plus the extended `check-agent-deps.sh`.
- [x] 6.2 Roadmap + decision register: HIPS-3 increment 2a done; state plainly that **intent-driven
  containment still needs SOAR-7**, so XDR-6 stays blocked, and record the fail-open trade and the cache
  staleness.
- [x] 6.3 Commit with the `HIPS-3` handle, sync the delta spec, archive the change.
