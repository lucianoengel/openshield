# Add parser sandbox hardening (T-012)

## Why

The privilege split (D13/D29) put content parsing in an unprivileged worker so that a parser
memory bug is not a host compromise. That boundary is necessary but not sufficient: an
unprivileged process can still open a socket and exfiltrate, or be driven to exhaust memory by a
decompression bomb. The precedent is not hypothetical — ClamAV **CVE-2025-20260**, a PDF-parser
heap overflow to RCE, is exactly the shape of bug the worker parses attacker-controlled bytes
into every day. D13 always specified seccomp + no-network + cgroup + bomb limits on the worker;
this builds them.

## What changes

**The worker installs a seccomp-bpf filter at startup, before it reads a single byte of
attacker-controlled input.** The filter denies the syscalls a file-scanning parser has no
business making — above all the network family (`socket`, `connect`, `bind`, …). A parser RCE in
a worker that *cannot call `socket`* cannot phone home, cannot exfiltrate over the network, and
cannot open a reverse shell — the capability is gone, not merely discouraged.

- Pure-Go filter (`elastic/go-seccomp-bpf`), applied with `NO_NEW_PRIVS` so it needs no
  privilege, and with TSYNC so it covers every Go runtime thread, not just the calling one.
- Default-allow with a network (and other dangerous-syscall) **denylist** for Phase 1, rather
  than a strict allowlist. An allowlist is stronger but brittle against the Go runtime's evolving
  syscall use; a denylist that provably removes network egress delivers the headline property
  now, and tightening to an allowlist is a later, testable step. This trade is stated, not hidden.

**Decompression-bomb limits before any parser runs.** The worker already caps raw input bytes
(`limitReader`) and the classifier uses a linear-time matcher (D33). This adds the missing
dimension: when a future detector decompresses, expansion is bounded by ratio, absolute expanded
size, and nesting depth, and a bomb is rejected **before** the parser is handed the expanded
stream — not discovered by OOM.

**cgroup memory/CPU limits are configured where the worker is supervised, not coded into it.**
In production systemd runs the worker under `MemoryMax`/`CPUQuota` (the supervisor's job, T-006's
deployment shape). This change documents the required limits and provides the unit-file settings;
it does not reimplement cgroup management in Go. What the process CAN enforce on itself — seccomp,
bomb limits — it does; what belongs to the supervisor is specified for the supervisor.

## What this does NOT claim or cover

- **It is not a complete sandbox.** A denylist seccomp filter blocks the categories named; it is
  not a proof that no dangerous syscall remains. The strong, tested claim is specific: the worker
  cannot open a socket. Broader hardening (strict allowlist, namespaces, no-new-mounts) is
  incremental and flagged.
- **It does not protect the privileged process.** That process never parses attacker bytes by
  construction (D29, `check-agent-deps.sh`); seccomp on the worker is defense in depth for the
  half that does parse, not a substitute for the split.
- **cgroup limits are not enforced by this code.** They are a supervisor responsibility; this
  change specifies them and any in-process fallback is best-effort, not the guarantee.
- **seccomp is not available on every platform.** Only Linux ships (D9). On a non-Linux dev build
  the filter is a no-op that is loud about being absent, so a developer is never misled into
  thinking a Mac test run exercised the sandbox.
- **It does not stop a bomb that fits under the raw byte ceiling.** The byte ceiling and the
  expansion limits are different guarantees; a small compressed file that expands hugely is what
  the expansion limits catch, and a huge raw file is what the ceiling already catches.

## Decisions

Depends on **D13** (unprivileged sandboxed worker; seccomp + no-network + cgroup + bomb limits;
ClamAV precedent) and **D29** (two binaries; the privileged one never holds parser deps).

Establishes a small new decision: **the worker self-applies a seccomp network-deny filter before
touching input, as a denylist in Phase 1**, with the explicit intent to tighten toward an
allowlist later — the property delivered now is that a worker RCE cannot reach the network.
