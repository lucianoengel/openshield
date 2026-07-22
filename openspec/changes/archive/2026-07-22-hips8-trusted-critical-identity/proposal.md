## Why

The KILL safety allowlist is self-defeating. `isCriticalProcess` keys on the kernel `comm`
(`/proc/<pid>/comm`), which a process sets for itself via `prctl(PR_SET_NAME)` / `argv[0]`. So
malware that names itself `sshd`, `systemd`, or `openshield*` becomes **permanently unkillable** by
HIPS — it opts *into* the protection meant to guard the host. This is worse than a renamed-LOLBin
detection evasion: it grants immunity from *containment*, not just detection. The guard must key on an
identity the process cannot forge.

## What Changes

- Identify a critical process by its **real executable** (`/proc/<pid>/exe`, kernel-maintained, not
  settable by the process) plus that binary's **ownership**, not by `comm`. A process is protected
  only when its real exe is **root-owned and not writable by non-owners** AND its basename is a
  critical name (init/systemd/sshd/db/runtime) or a fleet binary (`openshield*`).
- A non-root attacker cannot create a root-owned binary, so cannot get a renamed process protected —
  the self-immunization is closed. (A root attacker already defeats host controls, D16, and can kill
  the enforcer regardless.)
- The enforcer's injectable identity seam changes from `nameOf(pid) → comm` to
  `identify(pid) → {exePath, rootOwned, otherWritable}`, so the trusted-identity logic is unit-tested
  without needing root: a self-renamed non-root process is still killed; a root-owned critical binary
  is spared.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `enforcement`: the kill enforcer identifies a critical process by a trusted identity (its real,
  root-owned executable), not by the self-settable process name — a process that merely renames itself
  to a critical name is still terminated.

## Impact

- **Code:** `internal/enforcers/process/process.go` (the critical check + the `identify` seam),
  `internal/enforcers/process/kill_linux.go` (real `/proc/<pid>/exe` + ownership), the darwin/other
  stubs, and the tests. No change to the pid-reuse mechanism (HIPS-7, separate) beyond keeping the
  seam it will extend.
- **No proto/core change**; `KILL_PROCESS` and the enforcer interface are unchanged.
