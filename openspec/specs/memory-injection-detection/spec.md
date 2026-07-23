# memory-injection-detection Specification

## Purpose
Detect a process running injected code by its structural signature — a memory region that is BOTH writable
and executable (a W^X violation) — independent of the code's content. Legitimate code is mapped
read-execute from a file; code written into a process at runtime lives in a writable page that is also
executable. Scanning reads only memory-map metadata (address ranges, permissions) and the executable path,
never process memory contents, and a cross-process scan skips any process it cannot read so an unprivileged
run covers its own processes and a privileged run covers the whole fleet. A detection enters the pipeline as
a content-free high-severity event for a policy alert. Real-time (eBPF/LSM) detection, a JIT allowlist, and
non-W^X injection techniques are follow-ups.

## Requirements
### Requirement: Detect writable-and-executable memory as an injection signal

The system SHALL scan a process's memory map and flag any region that is BOTH writable and executable (a
W^X violation) as a suspected code-injection signal, and SHALL NOT flag a region that is executable but
not writable (normal code) or writable but not executable (normal data). Scanning MUST read only the
memory-map metadata (address ranges and permissions) and the process's executable path — it MUST NOT read
the process's memory contents. A scan across processes MUST skip a process whose map it cannot read (a
different user's process without privilege, or one that has exited) rather than fail, so an unprivileged
scan covers its own processes and a privileged scan covers all of them.

#### Scenario: A writable-executable region is flagged
- **WHEN** a process has a memory region mapped both writable and executable
- **THEN** that process is flagged as a suspected injection

#### Scenario: Normal code and data regions are not flagged
- **WHEN** a process has only read-execute (code) and read-write (data) regions
- **THEN** it is not flagged

#### Scenario: An unreadable process is skipped, not fatal
- **WHEN** a process's memory map cannot be read during a scan
- **THEN** that process is skipped and the scan continues

### Requirement: A memory-injection detection enters the pipeline as a high-severity event

The system SHALL emit a suspected code injection as a distinct high-severity event carrying the process id
and executable path but no memory content, so a policy can decide (for example, alert). The event MUST
reach the policy on its metadata — the pipeline MUST NOT attempt to read the flagged process's memory. A
standing suspect MUST NOT re-emit on every scan (a new suspect is a not-previously-seen process).

#### Scenario: A detection becomes a policy alert
- **WHEN** the scanner flags a process with writable-executable memory
- **THEN** a content-free memory-injection event flows the pipeline to the policy, which can alert, without reading the process's memory
