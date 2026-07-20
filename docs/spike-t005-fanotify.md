# Spike T-005 — what fanotify actually delivers

**Date:** 2026-07-20 · **Settles:** the path-vs-handle `oneof` in T-003 ·
**Code:** [`../spikes/t005-fanotify/`](../spikes/t005-fanotify/)

## Questions

1. Does a fanotify listener receive a resolvable path or an opaque kernel handle? The T-003
   event schema modelled this as a `oneof` because nobody had checked, and that was flagged as
   the design's weakest point.
2. Is `golang.org/x/sys/unix` sufficient, or does the agent need CGO? (Review finding A3, open.)

## Results

Kernel 7.0.0, unprivileged (`coder`, no capabilities).

| init mode | opens? | identity delivered | resolvable to a path? |
|---|---|---|---|
| `FAN_CLASS_NOTIF` (classic) | **EPERM** | *(fd per event)* | not measurable here — needs `CAP_SYS_ADMIN` |
| `FAN_CLASS_NOTIF｜FAN_REPORT_FID` | yes | opaque file handle | **no** — `open_by_handle_at` → EPERM |
| `FAN_CLASS_NOTIF｜FAN_REPORT_DFID_NAME` | yes | parent handle **+ filename** | **yes, partially** — name is in the event, no capability needed |
| `FAN_CLASS_CONTENT` (blocking) | **EPERM** | *(fd, permission events)* | needs `CAP_SYS_ADMIN` |

Observed event in DFID_NAME mode:

```
event: mask=CREATE pid=1314551 fd=-1 len=68
  identity: DFID_NAME record — parent handle + name "customers.csv"
```

`open_by_handle_at` on the FID-mode handle fails with EPERM, as expected without
`CAP_DAC_READ_SEARCH`.

## Verdict for the schema: keep the `oneof`, but it needs a **third** arm

The original justification was wrong, and the conclusion survives for a better reason.

It was written as "we don't yet know which form arrives". The real answer is that **both arrive,
and which one depends on a coverage decision the agent makes**:

- **Classic mode** (`CAP_SYS_ADMIN`, per-directory marks) hands over a **file descriptor** per
  event. `readlink /proc/self/fd/N` yields a path with no further capability. This is the
  straightforward case and the one the shipped agent will use for targeted watches.
- **FID mode** exists so a single `FAN_MARK_FILESYSTEM` can cover a whole filesystem without an
  fd per event — which round-1 scouting identified as what makes fanotify practical for
  whole-disk coverage rather than per-directory bookkeeping. It delivers a **handle**, and
  resolving it needs `CAP_DAC_READ_SEARCH`.
- **DFID_NAME mode** delivers a **parent handle plus the filename**. The name needs no
  capability, but a name alone is not a path — reconstructing one requires either knowing the
  watched directory (fine for targeted marks) or resolving the parent handle (back to
  `CAP_DAC_READ_SEARCH` for filesystem-wide marks).

So the schema's two-arm `oneof` is **incomplete**. It needs three arms:

```
oneof subject {
  string resolved_path        // classic mode: fd -> readlink
  bytes  file_handle          // FID mode: opaque, needs CAP_DAC_READ_SEARCH
  ParentAndName parent_name   // DFID_NAME mode: parent handle + filename
}
```

**Action:** revise `specs/event-contract/spec.md` before T-007/T-008/T-009 build on it. This is
the escape hatch the T-003 proposal reserved, used as intended.

## No CGO needed

`x/sys/unix` provides `FanotifyInit`, `FanotifyMark`, `OpenByHandleAt`, `NewFileHandle` and
every `FAN_*` constant used here. Event *parsing* is not provided — `fanotify_event_metadata`
and the `fanotify_event_info_*` records are laid out by hand — but that is ~60 lines of
`encoding/binary` and `unsafe.Pointer` over a stable ABI, not a reason to reach for CGO.

**Review finding A3 is closed: the agent stays pure Go.**

## Kernel floor

`FAN_REPORT_FID` requires 5.1; `FAN_REPORT_DIR_FID` and `FAN_REPORT_NAME` (together
`FAN_REPORT_DFID_NAME`) require 5.9. Unprivileged `FAN_CLASS_NOTIF` with `FAN_REPORT_FID`
requires 5.13. Classic privileged mode goes back to 2.6.37. A floor of **5.9** covers every mode
the design uses; unprivileged operation would need 5.13 but is not a product requirement.

## What could not be measured, and what that means

**Classic mode and permission events both returned EPERM**, so the fd → `readlink` path was not
exercised. That behaviour is well documented and is the oldest part of the fanotify ABI, but it
is *documented, not measured* — and this session already produced one benchmark whose results
looked plausible and were wrong.

The dev sandbox cannot obtain real `CAP_SYS_ADMIN`: rootless Podman's userns capability is not
the same capability, which was measured earlier. Per the project's own scope rule, when the dev
loop needs a capability the answer is to **ask for it**, not to redesign around its absence.

**Open request to the host owner:** grant `coder` the ability to run this spike with
`CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` — via `setcap` on a test binary, a privileged
container, or a VM — so classic mode and permission-event delivery can be verified rather than
assumed. Not blocking: the schema decision above holds either way, because it must accommodate
all three identity forms regardless of which the agent ends up preferring.

## Bearing on classification

In FID mode without `CAP_DAC_READ_SEARCH`, the agent can see *that* a file changed but cannot
open it to classify. In production the agent holds that capability, so this is a dev-loop
limitation only — the earlier R1 question is answered: **content reading works in production,
and does not work in this sandbox.**
