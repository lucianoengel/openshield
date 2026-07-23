## Why

HIPS-3 (D217) built and mutation-tested the exec inline-block *decision logic* — the `ExecEvaluator`
that answers the kernel DENY iff a decision is `DENY_EXEC`, the `FanotifyResponder` deny path, and the
fail-open watchdog — but **without root**, so the actual kernel producer that marks and reads
`FAN_OPEN_EXEC_PERM` events was deferred. A rooted test VM (kernel 6.8, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`)
is now available, so this increment builds that producer and proves inline exec **prevention** on a live
kernel — OpenShield's first true endpoint deny (a kernel-level refusal), not post-hoc containment.

## What Changes

- **A discovered architectural constraint, resolved.** `cmd/openshield-agent` is guarded by
  `check-agent-deps.sh`, which bans `encoding/json` from the privileged binary — and `corev1` (protobuf)
  transitively pulls `encoding/json`. The `watchdog` package currently imports `corev1` (via
  `execeval.go`), so it can't live in the parser-free privileged binary. **Refactor:** move
  `ExecDecider`/`ExecEvaluator` from `watchdog` → `execguard` (which already holds the corev1↔engine
  bridge), leaving `watchdog` parser-free.
- **New `internal/agent/execmon`** (linux; portable stub) — the fanotify exec-permission **producer**:
  `FanotifyInit(FAN_CLASS_CONTENT)` + `FanotifyMark(FAN_OPEN_EXEC_PERM)` on watched paths; a read loop
  that decodes each `fanotify_event_metadata` into a `watchdog.PermissionEvent{PID, FD, Path}`, drives
  `watchdog.Handle` (allow/deny under the budget + self-PID exemption + fail-open), and **closes the
  event fd**. Robust to short/malformed reads — it always answers the kernel and never hangs (a parked
  exec'ing process blocks uninterruptibly, so robustness is safety).
- **A pure, parser-free inline exec `Evaluator`** — an operator application **deny-list** (exec
  paths/basenames) plus an optional `internal/behavioral` score threshold (LOLBin / lineage /
  encoded-command, all json-free) → `VerdictBlock`, else `VerdictAllow`. Real inline exec prevention
  (also a slice of HIPS-4 application-whitelisting) that fits the budget with **zero IPC** and holds no
  parsers.
- **Wiring:** `cmd/openshield-agent` (its first real function) runs the monitor behind
  `OPENSHIELD_EXEC_MONITOR_DIRS` + `OPENSHIELD_EXEC_DENY`; still passes `check-agent-deps`.

## Capabilities

### New Capabilities
<!-- none — extends the existing inline-prevention capability (HIPS-3). -->

### Modified Capabilities
- `inline-prevention`: add the privileged fanotify **exec-permission producer** that realizes the
  already-specified "a DENY_EXEC decision inline-blocks an exec" behavior on a live kernel, and add
  **parser-free inline exec deny-listing** as the increment-1 decider the privileged binary can hold.

## Impact

- **Code:** move `execeval.go` → `execguard`; new `internal/agent/execmon/` (producer + pure evaluator);
  `cmd/openshield-agent/main.go` (real exec-monitor). No proto, no migration, no new dependency
  (`golang.org/x/sys/unix` already vendored).
- **Testing:** metadata-decode + evaluator unit tests run everywhere (no root); a **gated** real-kernel
  integration test (`requireExecPerm`) skips without root (like the swtpm tests) and is proven on the VM
  via `go test -c` + `scp` + `sudo`.
- **Deferred (increment 2, stated honestly):** driving the FULL OPA-pipeline `DENY_EXEC` decision inline
  (the privileged binary can't hold the policy engine/proto — needs an IPC-to-engine decider, for which
  the relocated `execguard.ExecEvaluator` becomes the bridge); `FAN_MARK_MOUNT` whole-filesystem
  coverage; the file-open DLP inline path (still budget-blocked, D49); non-Linux.
