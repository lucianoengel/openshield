## ADDED Requirements

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
