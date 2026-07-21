## Context

The worker (`cmd/openshield-worker`, `internal/agent/worker`) reads ClassifyRequests, opens the
named file with its own unprivileged credentials, and runs the classifier. It already bounds raw
input (`limitReader`) and uses RE2 (D33). It has no syscall restriction and no decompression
handling. seccomp on Linux can be self-applied with `PR_SET_NO_NEW_PRIVS`, which needs no
privilege; the probe confirmed `socket()` returns EPERM after loading a network-deny filter with
TSYNC in this environment.

## Goals / Non-Goals

**Goals:**
- The worker cannot open a socket, enforced by a filter it installs on itself before reading
  input, covering all runtime threads.
- Decompression expansion is bounded (ratio, absolute size, depth) and a bomb is rejected before
  a parser sees the expanded bytes.
- cgroup limits specified for the supervisor; a loud no-op on non-Linux.

**Non-Goals:**
- A strict syscall allowlist (brittle against the Go runtime; a later tightening).
- In-Go cgroup management (systemd's job).
- Protecting the privileged process (it never parses; D29).

## Decisions

### seccomp lives in `internal/agent/sandbox`, applied from the worker main
`sandbox.Apply()` builds a `seccomp.Policy` (default allow) with an ActionErrno group naming the
network syscalls (`socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`, `accept4`,
`sendto`, `recvfrom`, `sendmsg`, `recvmsg`, plus `ptrace` and friends) and loads it with
`NoNewPrivs: true, Flag: FilterFlagTSync`. Called in `main` BEFORE the read loop — the filter
must be in force before the first attacker byte is read, or a fast exploit races it.

The denylist over allowlist choice: an allowlist would break whenever the Go runtime starts using
a new syscall (a GC or scheduler change), turning a runtime upgrade into a worker crash. The
denylist delivers the property that matters — no network — without that fragility. The design note
and the decision record both say the intended end state is an allowlist.

### Non-Linux is a loud no-op
`sandbox_linux.go` / `sandbox_other.go` build-tagged. The non-Linux `Apply` returns a sentinel
`ErrUnsupported` (not nil), and the worker main logs it prominently. A developer on macOS must
see "SANDBOX NOT APPLIED" rather than a silent pass that looks like success. Only Linux ships
(D9), so production is always the real path.

### Bomb limits are a decompression guard, separate from the byte ceiling
`sandbox.DecompressGuard` wraps a decompressing reader with three bounds:
- **ratio**: output bytes / input bytes may not exceed a cap (e.g. 200:1);
- **absolute**: total output bytes may not exceed a cap;
- **depth**: nested archives may not exceed a depth cap.
Exceeding any is an error returned BEFORE the caller receives the over-limit bytes — a bomb hits
the guard, not memory. Phase 1 has no decompressing detector, so the guard ships with a test and
is wired where decompression will land; shipping it now keeps the bomb defense from being an
afterthought when the first archive detector arrives.

### cgroup limits: specified, not coded
A systemd unit fragment (`MemoryMax`, `MemorySwapMax=0`, `CPUQuota`, `TasksMax`) documented in the
worker package doc and provided as a drop-in. The process cannot reliably set its own cgroup
limits without privilege; pretending to in Go would be theatre. The honest split: self-applicable
protections (seccomp, bomb limits) are code; supervisor-applied ones are configuration.

## Risks / Trade-offs

- **Denylist completeness.** A syscall we forgot to deny remains available. The tested claim is
  narrow and true (no `socket`); it is not "fully sandboxed". Tightening is incremental.
- **TSYNC and Go threads.** The Go runtime multiplexes goroutines across threads created at
  arbitrary times; TSYNC applies the filter to all existing threads and NO_NEW_PRIVS makes it
  inherit to new ones. The probe confirmed a socket call from the main thread is blocked; a test
  also spawns goroutines to confirm the filter is not thread-local.
- **A denied syscall the runtime needs would crash the worker.** Mitigated by denying only a
  conservative dangerous set (network, ptrace), not core file/memory syscalls the runtime needs.
- **The guard ships unused in Phase 1.** Deliberate: the alternative is remembering to add bomb
  defense under deadline when the first archive detector lands, which is how bomb defenses get
  skipped.
