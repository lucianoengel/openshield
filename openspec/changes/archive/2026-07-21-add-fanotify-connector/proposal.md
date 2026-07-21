# Add the fanotify observe connector — the real front-end (Direction 2)

## Why

The walking-skeleton engine is fed by synthetic events in tests; the real fanotify front-end — the
thing that turns actual file activity into Events — was left as "privilege-gated, covered by the
spike". Probing settled what is actually possible: fanotify PERMISSION mode (blocking) needs
init-namespace CAP_SYS_ADMIN and is unavailable here (even `--privileged` rootless podman), and FID
handle resolution needs CAP_DAC_READ_SEARCH, also unavailable. BUT fanotify NOTIFY mode with
`FAN_REPORT_DFID_NAME` WORKS unprivileged, and for a per-directory watch the file path is simply
`watchedDir + "/" + name` from the event — no privileged handle resolution needed. So the OBSERVE
front-end is fully buildable and runnable here, and it can drive the engine to a real audit row from
a real file change. This builds it.

## What changes

**A fanotify observe connector (`internal/connectors/fanotify`).** It watches configured directories
in notify mode (`FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME`), decodes each event's mask and filename,
and produces `EVENT_KIND_FILE_MODIFIED` / `FILE_CREATED` Events whose resolved path is
`watchedDir/name`. The event-metadata parsing is a pure function tested against byte layouts; the
live watch is exercised against real files.

**Wired to the engine, end to end, unprivileged.** A test watches a directory, writes a file
containing a seeded CPF, and asserts the connector's event flows through the engine (real worker
classifies → policy → audit) to a verifiable ledger entry — a genuine kernel-event → audit run that
runs HERE, no privilege.

**The privileged limits recorded from measurement, not assumption.** Permission mode (inline
blocking) needs init-namespace CAP_SYS_ADMIN; recursive/filesystem marks and FID resolution need
CAP_DAC_READ_SEARCH. Both were probed and confirmed unavailable in rootless podman. The connector
handles the per-directory observe case that works unprivileged; the blocking and handle-resolution
paths are the documented privileged edge, consistent with the deferred inline-blocking (T-002).

## What this does NOT claim or cover

- **It does not block.** Notify mode observes; it cannot deny a file open (that is permission mode,
  privileged and deferred, T-002). Observe-only (D1) is exactly what notify mode provides.
- **It does not resolve FID handles.** For a per-directory watch the path is `dir/name` and needs no
  resolution; a recursive/filesystem mark where the parent is a subdirectory WOULD need
  `open_by_handle_at` (CAP_DAC_READ_SEARCH, unavailable here) — that broader watch is the privileged
  extension, stated.
- **It does not run in the privileged agent's dependency graph in a way that breaks D29.** The
  connector produces Events (paths only, no content); it does not parse. The privileged agent
  remains parser-free; classification stays in the worker.
- **It is a connector, not the whole agent.** Wiring directory configuration, the privileged
  permission responder, and multi-directory management into the shipped agent binary is the
  remaining assembly; this delivers the observe connector and proves it drives the engine.

## Decisions

Depends on **D1** (observe-only), **D24** (the pipeline the events feed), **D48** (the engine),
**D29** (paths not content), and the PROBED facts about fanotify privilege in rootless podman.

Establishes a new decision: **the fanotify observe front-end uses NOTIFY mode with per-directory
watches, resolving paths as `watchedDir/name` without privileged handle resolution — which works
unprivileged; permission mode (blocking) and recursive/filesystem marks (FID resolution) are the
privileged edge, confirmed by probe to be unavailable in rootless podman and consistent with the
deferred inline blocking.**
