## Why

D330 fixed the exec allowlist's *decision* and left its *cost* — stated plainly at the time: the agent
still answers a fanotify permission event for every execution on the marked mount, and each one blocks
the executing process while a readlink and a kernel round-trip happen. On a busy host that is overhead on
the critical path of every process launch, for executions the agent has already decided it does not
police.

## What Changes

Measured on the rooted VM (kernel 6.8), because the reason the mount mark exists is that a narrower one
was tried and did not work:

| mark | direct child | nested | outside |
|---|---|---|---|
| mount (status quo) | delivered | delivered | not delivered |
| directory + `FAN_EVENT_ON_CHILD` | **EINVAL — the kernel refuses the mark** | — | — |
| per-file | delivered | not delivered | not delivered |

- **Per-file marks are used when the gate's semantics are SCOPED** — that is, when an allowlist is the
  configured signal, whose scope D330 already defined as the monitored directories. Executions elsewhere
  then generate no event at all.
- **The mount mark is kept when the semantics are GLOBAL** — a deny-list names binaries to refuse
  *wherever they run from*, and the behavioural floor and the IPC gate likewise decide on anything they
  are shown. Narrowing those would silently reduce what they catch.
- **New files are marked as they appear.** Per-file marks cover files that exist when the mark is
  applied; a binary dropped into a watched directory afterwards would otherwise be unmarked and, under
  default-deny, would RUN. An inotify watch marks it on create/move/close-write.

`FAN_EVENT_ON_CHILD` would have been the better answer — one mark per directory, new files covered by the
kernel — and it is not available: the kernel rejects it for exec-permission events. That is now recorded
in a test rather than in a comment.

## Capabilities

### Modified Capabilities

- `inline-prevention`: the mark's breadth becomes a stated requirement tied to the gate's semantics, and
  the coverage of newly-created files becomes explicit rather than incidental.

## Impact

- `internal/agent/execmon` — mark selection, enumeration, and an inotify re-marker.
- No configuration change, no proto change, no new dependency (`golang.org/x/sys/unix` is vendored).
- **The risk is a coverage regression, and it is the whole risk.** Per-file marking can only miss things;
  the mount mark can only waste. So the narrowing is applied ONLY where scope is already defined, the
  new-file path is closed explicitly, and the residual race (create → exec before the watcher marks) is
  stated rather than papered over.
