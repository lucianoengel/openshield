# Agent Process Boundary

## Purpose

The two-binary privilege split between the agent that holds CAP_SYS_ADMIN and the worker that parses attacker-controlled files, the IPC contract between them, and the rule that content never crosses into the privileged process.

> Synced from change `add-agent-process-boundary` on 2026-07-20.
> Implemented in `internal/agent/*` and `cmd/openshield-worker`; guards mutation-tested.

## Requirements
### Requirement: The privilege split is two separate binaries
The privileged agent and the parser worker MUST be distinct binaries. A single binary selecting
behaviour by flag SHALL NOT be used.

A single binary carries the parser packages in its dependency graph regardless of which code
path executes, which makes the import check — the only mechanism keeping this boundary real
rather than aspirational — prove nothing.

#### Scenario: The privileged binary cannot link a parser
- **WHEN** CI computes the dependency graph of `cmd/openshield-agent`
- **THEN** it contains no `archive/*`, `compress/*`, `encoding/{json,xml,csv,asn1,gob,pem}`,
  `text/template`, `html/template`, `image/*` or document-parser package
- **AND** the check fails the build rather than warning
- **AND** the check itself is verified by adding such an import and observing the failure

### Requirement: Attacker-controlled content never reaches the privileged process
The privileged process MUST NOT read, receive or hold attacker-controlled file content. The
worker SHALL open files with its own unprivileged credentials and return only detector types,
confidences and counts.

This is stronger than "does not parse". Receiving already-parsed content would still place
attacker data in the address space holding `CAP_SYS_ADMIN`, which is what the split prevents.
The precedent: ClamAV CVE-2025-20260, a PDF-parser heap overflow reachable in a privileged
daemon.

#### Scenario: The IPC response carries no matched content
- **WHEN** the classification response message is inspected
- **THEN** it carries detector type, confidence and count, and no field capable of holding
  matched text
- **AND** `LocalClassification` has no path from the worker to the privileged process

#### Scenario: The worker opens the file itself
- **WHEN** the privileged process requests classification
- **THEN** it sends a path, never file bytes
- **AND** the worker's access is bounded by ordinary filesystem permissions, not by
  `CAP_SYS_ADMIN`

### Requirement: The IPC framing bounds allocation before allocating
The IPC layer MUST reject a frame whose declared length exceeds the maximum **before** allocating
a buffer for it.

The length prefix arrives from the process that just parsed an attacker's document. An unbounded
prefix is a memory-exhaustion primitive costing four bytes.

#### Scenario: An oversized length prefix is rejected without allocating
- **WHEN** a frame header declares a length above the maximum
- **THEN** the read fails with a frame-too-large error
- **AND** no buffer of the declared size is allocated

### Requirement: Failure and truncation are never reported as clean results
The worker MUST distinguish "found nothing" from "could not look". A classifier error, an
unreadable file, or input truncated at the byte ceiling SHALL be reported explicitly.

Conflating them is the quietest possible failure in a detection product: a crashing parser makes
every file look clean, and silent truncation turns file size into an evasion technique — pad past
the ceiling and the payload is never examined.

#### Scenario: A classifier error is not a clean result
- **WHEN** the classifier returns an error
- **THEN** the response carries the error and no hits

#### Scenario: Truncation is reported
- **WHEN** a file exceeds the byte ceiling
- **THEN** the classifier sees no more than the ceiling
- **AND** the response is marked truncated

### Requirement: A hung worker is bounded and indistinguishable from a failed one
The privileged side MUST bound its wait for a worker response with a deadline.

Behind the pipeline sits a process blocked in `TASK_UNINTERRUPTIBLE`. An unbounded wait on the
less-trusted party is how a machine hangs.

#### Scenario: A worker that never responds times out
- **WHEN** the worker does not answer within the deadline
- **THEN** the privileged side returns a timeout error within that deadline

#### Scenario: A desynchronised response is rejected
- **WHEN** a response arrives whose request id differs from the request
- **THEN** it is rejected rather than accepted
- **AND** one file's findings are never attributed to another

### Requirement: In-process connector parsers contain a panic to one input
The engine MUST recover from a panic raised while parsing one attacker-influenced input in-process (a network datagram, an audit record, or an event in its processing loop), dropping and counting that input and continuing, so a crafted metadata input cannot crash the engine. This keeps the RCE-prone content parsing in the sandboxed worker unchanged (D29/D35).

#### Scenario: A crafted input that panics a parser does not crash the engine
- **WHEN** an in-process connector parse loop handles an input that panics its parser or sink
- **THEN** the panic is recovered, the input is dropped and counted, and the loop continues to process subsequent inputs
