## Context

`KillEnforcer.EnforceTarget` refuses a kill when `isCriticalProcess(k.nameOf(pid))` holds, where
`nameOf` = `procComm` = `/proc/<pid>/comm`. `comm` is the process's own choice (`prctl(PR_SET_NAME)`
sets it; it also defaults to `argv[0]`'s basename), so a process names itself `sshd` and becomes
unkillable. The allowlist's INTENT — spare init/systemd/sshd/the DB/the runtime/the fleet's own
binaries — is right; its identity SOURCE is forgeable.

## Goals / Non-Goals

**Goals:**
- Key critical-process protection on an identity the target cannot forge.
- A self-renamed non-root process is still terminated; a genuine root-owned critical/fleet binary is
  still spared.
- Keep the guard unit-testable without root, via an injectable identity seam.

**Non-Goals:**
- The pid-reuse revalidation (HIPS-7) — a separate ticket; this change keeps the seam it extends.
- Protecting against a root attacker (out of the host-control threat model, D16).
- A cgroup/systemd-unit scheme — `/proc/<pid>/exe` + ownership is simpler, as portable, and as
  spoof-resistant for this threat (a non-root process cannot own a root binary).

## Decisions

### D-a · Trusted identity = the real executable + its ownership
Replace the `nameOf(pid) (string, error)` seam with `identify(pid) (procIdentity, error)` where
`procIdentity = {ExePath string; RootOwned bool; OtherWritable bool}`. On Linux, `ExePath` is
`readlink(/proc/<pid>/exe)` (the kernel's record of the actual binary — not settable by the process);
`RootOwned`/`OtherWritable` come from `stat`-ing that path (uid 0; and mode & 022 for group/other
write). A process is critical iff:

```
RootOwned && !OtherWritable && (basename(ExePath) ∈ criticalNames || strings.HasPrefix(basename, "openshield"))
```

*Why exe, not comm:* `/proc/<pid>/exe` follows the inode the process actually exec'd; a process can
change `comm`/`argv[0]` freely but cannot make its exe point at a different file without exec'ing it.
*Why ownership:* a non-root attacker cannot create a root-owned, non-writable binary, so cannot get a
renamed process into the allowlist. A root attacker is already outside the model (D16).

*Alternative considered:* cgroup/systemd-unit match (`/proc/<pid>/cgroup` → `sshd.service`).
**Rejected for now** — cgroup v1/v2 + distro variance make it fiddly and hard to test reliably in
rootless CI, for no more security than exe+ownership against the non-root-rename threat. Notable as a
future hardening if unit-level identity is ever needed.

### D-b · Fleet self-protection moves from comm-prefix to the real binary
The fleet's own binaries (`openshield*`) are installed root-owned; keying on the real exe basename
(root-owned) protects them while a `/tmp/openshield-worker` copy a non-root attacker drops is not
root-owned → not protected → killable. The running enforcer's own pid stays separately guarded
(`selfPID`), unchanged.

### D-c · Missing/última identity is not a kill-blocker, but is fail-safe on error shape
If `identify` errors (process already gone, or non-Linux stub), the guard does what it does today:
`err == nil && isCritical` — an unreadable identity does not itself protect (a dead process is a
no-op kill anyway). The darwin/other stubs return an unsupported error, matching the existing
`procComm` stubs; `KILL_PROCESS` is Linux-only in practice.

## Risks / Trade-offs

- **A root-owned non-critical binary is killable** — correct; only the named criticals + fleet are
  spared. Protecting all root processes would be too broad.
- **A deployment that runs fleet binaries from a non-root-owned path loses fleet self-protection via
  this guard** — the `selfPID` guard still protects the live enforcer, and D16 bounds the rest; noted.
- **Testing the positive (root-owned → spared) without root** — handled by injecting a fake `identify`
  that reports `RootOwned:true`; the negative (self-rename → killed) is tested with a real non-root
  exe basename via the injected seam and, where feasible, a real spawned process.

## Migration Plan

Drop-in: the enforcer's public API is unchanged; only the internal identity source changes. No
deployment change. Rollback is reverting the commit (returns to the comm-based, spoofable guard).

## Open Questions

None for this threat model; cgroup-unit identity is a recorded future option (D-a).
