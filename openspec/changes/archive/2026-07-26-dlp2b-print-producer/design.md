## Context

CUPS runs a job through a chain of filter executables. Each reads the job on stdin (or a file argument),
writes the transformed job on stdout, and is invoked as
`filter job-id user title copies options [filename]`. **A filter's non-zero exit aborts the job**, which is
the property that makes prevention available: no hooking, no driver, no injection.

This is the print analogue of D247's clipboard mediation — the platform provides an interposition point and
we occupy it, rather than watching a spool directory after the fact.

## Goals / Non-Goals

**Goals:** intercept in the chain; classify in the sandboxed worker; allow or abort; content-free event;
print as an exfil channel; fail open loudly.

**Non-Goals:** watermarking/redaction, per-page verdicts, non-CUPS print paths, Windows spooler, OCR.

## Decisions

### D-1: A filter, not a spool watcher

*Alternative: watch `/var/spool/cups`.* Rejected — it observes after the decision to print is already
irreversible, which is the difference between an alert and a control. The filter contract gives both the
content and the veto.

### D-2: The filter is thin and parses nothing

It streams the job to the engine over a unix socket and applies the verdict. The classifier runs in the
worker, as everywhere else: a print filter runs on documents from anywhere, which is precisely the
attacker-controlled-bytes case D71 exists for. The filter's own logic is read, ask, copy-or-exit.

### D-3: Fail open, and say so

An unreachable engine, a timeout, or a protocol error prints the job and audits at high severity. Failing
closed would mean a dead daemon stops an office from printing — the fastest way to have the agent removed
entirely, which protects nothing. Same trade as the exec gate (D17/D73).

### D-4: Bounded, like every other content path

The job is streamed to the engine up to a cap; beyond it the verdict is requested on what was read and the
remainder passes through. A print job can be hundreds of megabytes and the filter must not buffer it all.

### D-5: Reuse the framing discipline, not the code

The verdict protocol mirrors `execipc`: fixed-shape header, bounded lengths validated before allocation,
request ids matched. It is a separate package because the payloads differ (a job carries content and
metadata, an exec carries a path) and because coupling the print path to the exec gate's wire format would
make one ticket's change break the other's.

## Risks / Trade-offs

- **Chain placement determines detection quality.** Inserted before rasterization the filter sees text;
  after, it sees raster bytes and detection is far weaker. Documented as an operator decision.
- **A large job costs memory and latency** in the engine. Bounded by the cap (D-4) at the cost of
  classifying only the head of a very large document — stated, not hidden.
- **Install requires root** and touches the printer's filter chain; a bad install breaks printing, so the
  filter must be conservative and pass through on any doubt (D-3).
- **Bypass paths exist** (direct-to-device, in-app PDF export). Named in the proposal.

## Migration Plan

Additive: nothing changes until the filter is installed into a printer's chain and the engine's listener is
enabled. Removing the filter from the chain restores stock behavior.

## Open Questions

- Should a denied job produce a printed banner page explaining the refusal? Useful for users, but it means
  emitting output for a job we just refused; deferred.
