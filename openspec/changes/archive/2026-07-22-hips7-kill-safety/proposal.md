# HIPS-7: KILL_PROCESS safety hardening

## Why

Now that KILL_PROCESS is runnable (HIPS-5a), its safety guards are too weak for a verdict that
terminates a process:
- **No critical-process protection**: it refused only its own pid and pid ≤ 1 — not the privileged
  agent, the worker, sshd, the database, or systemd. A wrong/forged verdict could take down the host
  or the platform itself.
- **pid reuse**: `platformKill` sent a plain `kill(pid)`, so if the target exited between the decision
  and the kill and its pid was recycled, it would kill whatever new (possibly critical) process now
  holds the number.
- **argc CPU-DoS**: `ParseExecve` looped `argc` times, each scanning the whole line, with `argc`
  taken unbounded from attacker-influenced audit text — a huge argc is a CPU denial-of-service.

## What Changes

- **Critical-process allowlist**: before killing, the enforcer reads the target's `comm` and REFUSES
  to kill init/systemd/sshd/login/the database/the container runtime, and any process whose comm
  begins `openshield` (the fleet's own binaries).
- **pid-reuse-safe kill (Linux)**: `platformKill` now uses a PIDFD — `pidfd_open` refers to the
  specific process instance and `pidfd_send_signal` targets it, so a recycled pid returns ESRCH
  rather than killing the new holder. An already-gone process is a no-op, not an error.
- **argc bound**: `ParseExecve` caps `argc` at a sane maximum, so a crafted argc cannot turn parsing
  into an O(argc·len) CPU-DoS.

## Impact

- Affected specs: `enforcement`, `execaudit-connector`
- Affected code: `internal/enforcers/process/{process,kill_linux,kill_darwin,kill_other}.go`,
  `internal/connectors/execaudit/execaudit.go`.
- Not in scope (stated): a cgroup/own-fleet membership check as an alternative to the name allowlist
  (the comm allowlist covers the concrete criticals; a cgroup check is a deployment-specific
  refinement); closing the full decide→kill reuse window via a process identity carried on the Event
  (the Event carries only the pid; the PIDFD closes the enforcer-internal window, the residual is
  narrow); DENY_EXEC (still deferred, HIPS-5a).
