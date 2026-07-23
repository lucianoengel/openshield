## Context

The watchdog (`internal/agent/watchdog`) owns the fail-open budget, self-PID exemption, and the
allow/deny answer; `FanotifyResponder` writes the kernel response; `PermissionEvent{PID, FD, Path}` is a
decoded event. D217 added `ExecEvaluator` (DENY_EXEC → VerdictBlock) but it imports `corev1`, which
transitively imports `encoding/json` — banned in the privileged `openshield-agent` by
`check-agent-deps.sh`. So the watchdog package cannot currently live in the privileged binary. The
missing piece for real inline exec prevention is the privileged fanotify producer that marks/reads
`FAN_OPEN_EXEC_PERM` and drives the watchdog.

## Goals / Non-Goals

**Goals:**
- A working fanotify exec-permission producer that inline-DENIES a real exec on a live kernel, proven by
  a gated real-kernel test.
- Keep the privileged binary parser-free (passes `check-agent-deps`).
- A pure, budget-fit inline exec decider (deny-list + behavioral) with zero IPC.

**Non-Goals (increment 2, stated in the spec):** the full OPA-pipeline DENY_EXEC decision inline (needs
an IPC-to-engine decider); `FAN_MARK_MOUNT` whole-fs coverage; the file-open DLP inline path (budget-
blocked, D49); non-Linux enforcement.

## Decisions

1. **Refactor `ExecEvaluator`/`ExecDecider` out of `watchdog` → `execguard`.** Only `execeval.go` taints
   `watchdog` with `corev1`/`json`. `execguard` already holds the corev1↔engine bridge (D217), so it is
   the natural home. After the move, `go list -deps ./internal/agent/watchdog` contains no
   `encoding/json`, and the producer + watchdog can live in the parser-free privileged binary. The
   relocated `execguard.ExecEvaluator` stays the bridge for increment 2's IPC decider.

2. **The producer decodes `FAN_CLASS_CONTENT` metadata, not FID mode.** Permission mode returns the
   classic `fanotify_event_metadata` (fixed 24 bytes: `Event_len, Vers, Metadata_len, Mask, Fd, Pid`)
   with a real fd — exactly what `FanotifyResponder` answers on. Decoding is a pure function over the
   byte slice (`unix.FanotifyEventMetadata`), unit-testable without root. The NOTIFY connector's FID
   parser does not apply.

3. **Every event answers the kernel exactly once and closes its fd.** `watchdog.Handle` answers
   allow/deny; the producer then `unix.Close(e.FD)`. A short read, a version mismatch, or a decode error
   must NOT leave the exec'ing process parked (it blocks uninterruptibly) — the producer answers ALLOW
   (fail-open) for anything it cannot decode and continues. This is a safety property: robustness of the
   reader is the difference between a fail-open and a hung host.

4. **The increment-1 decider is pure and parser-free.** A `DenyEvaluator` implements
   `watchdog.Evaluator` using an operator deny-list (exec path or basename) plus an optional
   `internal/behavioral` score threshold (json-free) — `VerdictBlock` on a deny-list hit or above the
   threshold, else `VerdictAllow`. No `corev1`, no OPA, no IPC — it fits the permission budget directly.
   This is genuine inline exec prevention (application deny-listing) and a slice of HIPS-4
   app-whitelisting. Path comes from `readlink(/proc/self/fd/<fd>)`; the exec'ing PID from the metadata.

5. **`openshield-agent` becomes real for the exec case.** It builds a `watchdog.Watchdog{Evaluator:
   DenyEvaluator, Responder: FanotifyResponder{NotifyFD}, SelfPID: getpid, Budget, Audit}` + `execmon`
   and runs it, behind `OPENSHIELD_EXEC_MONITOR_DIRS` + `OPENSHIELD_EXEC_DENY`. With no monitor
   configured it keeps the stub's non-zero exit (a do-nothing privileged agent must not read as healthy).
   `check-agent-deps` must still pass — imports are `execmon` + `watchdog` (now clean) + `behavioral`
   (clean), no `corev1`.

## Risks / Trade-offs

- **The privileged decider is a deny-list, not the full policy.** Increment 1 cannot express the OPA
  pipeline's DENY_EXEC inline (the binary can't hold the policy engine). This is honestly a narrower
  claim than "the pipeline decision inline"; it is still real prevention and the correct first step. The
  IPC decider that closes the gap is increment 2, and the relocated `ExecEvaluator` is its bridge.
- **fd-leak hazard.** Forgetting to close an event fd leaks fds until the process dies. Mitigated by a
  single close after `Handle`, and the gated test asserts `/proc/self/fd` does not grow across N execs.
- **A hung reader parks execs uninterruptibly.** Mitigated by the watchdog budget (already fail-open) and
  the producer answering ALLOW on any undecodable event; the gated test also covers the benign path.
- **Marked scope is per-dir (`FAN_MARK_ADD`), not whole-mount.** Deliberate for increment 1 (bounded,
  testable); `FAN_MARK_MOUNT` coverage is deferred.
- **The gated test needs root + a permission-capable kernel** and so is skipped in the default suite and
  the current CI — run on the VM and reported; a privileged CI job is a follow-up.
