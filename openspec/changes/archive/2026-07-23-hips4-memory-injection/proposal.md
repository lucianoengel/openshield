## Why

Code injection — writing shellcode into a running process and executing it (process hollowing, reflective
loading, `mprotect` to make a heap page executable) — is how modern malware runs without a file on disk,
evading the file-based controls (FIM, DLP, exec deny/allow) OpenShield already has. Its kernel-visible
signature is **writable-and-executable memory** (a `W^X` violation): legitimate code is mapped
read-execute from a file, while injected code lives in a writable page that is also executable. This is
the last HIPS-4 subsystem and it genuinely needs kernel access — scanning another process's memory map
requires root, so it is proven on the rooted VM.

## What Changes

- **New `internal/meminject`** — parse a process's `/proc/<pid>/maps` and flag any mapping that is BOTH
  writable and executable (the `W^X`-violation / injected-code signature). `ScanPID(pid)` returns a
  process's suspect regions; `ScanAll` iterates `/proc` and scans every process it can read (all of them
  under root).
- **A producer** — on a poll, scan running processes; a process with a W+X mapping emits a high-severity
  **memory-injection event** (carrying the pid and the executable path from `/proc/<pid>/exe`, no memory
  content) into the pipeline → policy → alert. Per-process dedup so a standing suspect does not re-fire
  every poll.
- **Proto (additive):** `EVENT_KIND_MEMORY_INJECTION_SUSPECTED = 12`; the engine classifies it
  metadata-only (a process's memory is not file content to open).

## Capabilities

### New Capabilities
- `memory-injection-detection`: detect code injection by scanning process memory maps for
  writable-and-executable regions (the W^X-violation signature) and emitting a high-severity event a
  policy can alert on.

### Modified Capabilities
<!-- none — the engine metadata-only classify of the new kind is carried by the new capability. -->

## Impact

- **Code:** new `internal/meminject` (maps parser + W+X scanner); a producer + wiring in
  `cmd/openshield-engine` (behind `OPENSHIELD_MEMSCAN_INTERVAL`); one additive proto enum value; the
  engine `classifyStage` treats the new kind as metadata-only. No migration, no new dependency.
- **Testing:** the maps parser + W+X detection are unit-tested (synthetic maps); a real-kernel test maps
  a genuine `rwx` region (via `mmap(PROT_READ|WRITE|EXEC)`) in the test process and asserts `ScanPID`
  finds it (no benign `r-x`/`rw-` mapping is flagged); a **gated VM test** scans a DIFFERENT-user process
  as root — the genuinely root-required fleet-scan path.
- **Honest limitation:** some JIT runtimes (JVM, V8/Node, LuaJIT) legitimately create W+X (or transiently
  rwx) mappings — a real deployment needs a process-name allowlist to suppress those. Increment 1 flags
  the raw signal and documents the allowlist as the next refinement; deferred too: reflective-DLL /
  hollowing-specific heuristics, and periodic vs on-exec scanning.
