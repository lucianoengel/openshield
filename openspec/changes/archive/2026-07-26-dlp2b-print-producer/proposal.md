## Why

Print is the other endpoint exfil channel a DLP is expected to cover, and OpenShield does not see it at
all: a user can print a sensitive document and nothing observes it, let alone stops it.

Real endpoint DLP does not watch the spool directory after the fact — it sits **in the spooler's filter
chain**, sees the job data, and can fail the job. CUPS is built for exactly that: a filter is an executable
in the chain that reads the job on stdin, writes it on stdout, and whose non-zero exit **aborts the job**.
That makes prevention available without hooking anything, the same way owning the X11 selection made
clipboard prevention available (D247).

## What Changes

- **A CUPS filter binary** (`openshield-print-filter`) that sits in the print chain: it passes the job
  through unchanged when allowed, and exits non-zero — aborting the job — when denied.
- **A print-verdict path to the engine**: the filter asks the engine over a unix socket, the engine
  classifies the job content in the **sandboxed worker** and runs the policy, and answers allow/deny. The
  filter itself never parses the job.
- **A content-free print Event** (`EVENT_KIND_PRINT_JOB` + `PrintSubject`) carrying job metadata — printer,
  byte count, page count where known, and the submitting user — never the document.
- **`ChannelPrint`** joins the exfil channel model, so a channel-aware policy gates printing with the same
  rule shape it uses for removable media, cloud sync and the clipboard.
- **Fail-open, loudly:** if the engine is unreachable or slow, the job PRINTS and the fail-open is audited
  at high severity. A DLP that stops the office printing because a daemon died is a DLP that gets removed.

## Capabilities

### New Capabilities

- `print-monitor`: intercepting a print job in the spooler filter chain, classifying it in the sandboxed
  worker, and allowing or aborting it under policy.

### Modified Capabilities

- `event-contract`: adds the print event kind and its content-free subject.
- `exfil-channel-awareness`: print becomes a first-class exfiltration channel.

## Impact

- **Code:** new `cmd/openshield-print-filter`, new `internal/printguard` (framing, client, engine-side
  server), proto additions, `internal/exfil`, `internal/policy` mapping, engine wiring.
- **Decisions:** depends on **D10/D29** (job content to the worker, never onto an Event), **D71** (the
  process holding the bytes is not the one parsing them), **D17** (fail-open, audited), **D13** (the
  privileged agent is not involved), **D194** (channel model).
- **Deployment:** the filter must be installed into the CUPS filter path and referenced by the printer's
  PPD/`cups-filters` chain — a root-level install step, documented, not automatic.

### What this change does NOT claim or cover

- **It sees what the filter chain gives it.** Depending on where it is inserted, that is PostScript/PDF
  or an already-rasterized stream; a raster job is classified as bytes with far weaker detection than text.
  Placement in the chain determines detection quality, and that is an operator decision we document rather
  than hide.
- **It does not cover printing paths that bypass CUPS** — a direct-to-device print, a network printer
  addressed straight from an application, or a virtual PDF printer implemented in-app.
- **It does not watermark, redact, or modify** the job. Allow or abort, nothing in between.
- **Fail-open means a dead engine prints everything**, audited. That is the deliberate availability trade
  (D17), not a claim of unconditional coverage.
- No Windows print-spooler producer (PLAT-7 enrichment), no OCR of rasterized output, and no per-page
  decisions — the verdict is for the whole job.
