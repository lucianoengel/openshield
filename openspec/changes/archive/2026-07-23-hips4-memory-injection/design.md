## Context

`/proc/<pid>/maps` lists a process's memory regions, one per line:
`start-end perms offset dev inode pathname`, where `perms` is e.g. `r-xp` / `rw-p` / `rwxp`. Legitimate
executable code is `r-xp` mapped from a file; injected code is a writable page (`w`) that is also
executable (`x`). Reading a same-uid process's maps is unprivileged; reading a DIFFERENT user's process
needs root — which is why a fleet-wide scan is a privileged, VM-proven capability.

## Goals / Non-Goals

**Goals:** parse maps, flag W+X regions (the injection signature), scan processes, emit a high-severity
event for a policy alert; prove the cross-user (root) scan on the VM.

**Non-Goals:** a JIT allowlist (deferred refinement); hollowing/reflective-load-specific heuristics;
reading/dumping the injected bytes (only the region metadata crosses); on-exec (vs poll) scanning.

## Decisions

1. **W+X is the signal.** A mapping whose perms contain BOTH `w` and `x` is flagged — writable executable
   memory is the `W^X`-violation that injected shellcode needs. This is a stronger, lower-false-positive
   signal than "anonymous executable" (which many JITs trigger with a normal `r-xp`), because a mapping
   that is *simultaneously* writable and executable is rare in well-behaved software (most JITs enforce
   `W^X` by `mprotect`-ing to `r-x` after writing). The JIT residue that remains rwx is handled by a
   deferred process-name allowlist; increment 1 flags the raw signal and documents the trade-off.

2. **Metadata only — never read the memory.** The event carries the pid, the executable path
   (`/proc/<pid>/exe`), and the region address range/perms — NOT the memory contents. OpenShield never
   dumps a process's memory (privacy + it would need `process_vm_readv`, which the worker sandbox denies).
   The engine classifies the event metadata-only (like `FILE_DELETED`/ransomware), so nothing tries to
   "open" the process.

3. **`ScanAll` skips what it cannot read.** Iterating `/proc/<pid>`, a maps file it cannot open (a
   different user's process without root, or a process that exited) is skipped, not fatal — so an
   unprivileged run scans its own processes and a root run scans the whole fleet. `procRoot` is injectable
   (`/proc` in prod) so tests can point at a fixture tree.

4. **Per-process dedup in the producer.** A standing W+X process would otherwise re-fire every poll. The
   producer remembers the (pid, exec-path) it has already alerted on and re-alerts only a NEW suspect (a
   pid that recycles to a different exec path is a new suspect). Poll interval is operator-tuned.

5. **Additive event kind, metadata-only.** `EVENT_KIND_MEMORY_INJECTION_SUSPECTED = 12`; the policy routes
   it as high-severity (alert now; contain via SOAR-7 later).

## Risks / Trade-offs

- **JIT false positives.** JVM/V8/LuaJIT and some interpreters use W+X or transient rwx. Increment 1 will
  over-fire on those; the mitigation (an operator process-name/path allowlist, like the exec allowlist) is
  a documented next refinement, not shipped here. The honest signal is more useful surfaced than hidden.
- **Poll, not real-time.** Injection between polls that reverts (`mprotect` back to `r-x` after running) is
  missed. On-exec / mprotect-hook (eBPF) scanning is a deferred, heavier increment; the poll catches
  standing W+X memory (the common persistent case).
- **Root for a fleet scan.** Same-uid processes are scannable unprivileged; the whole fleet needs root.
  The gated VM test proves the cross-user root path; the producer logs how many processes it could not
  read (a hint that it needs more privilege).
- **No memory content.** By design OpenShield does not read the injected bytes — it reports the region, so
  an analyst investigates out of band. This bounds privacy exposure and the sandbox contract.
