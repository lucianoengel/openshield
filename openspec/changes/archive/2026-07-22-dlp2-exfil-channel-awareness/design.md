## Context

`buildInput` already computes content-free derivations from event metadata (the behavioral analysis from
process exec fields). The exfil channel is the same kind of thing: a pure function of the file path,
carrying no content. So it is computed in the mapping for a filesystem event and exposed as
`input.event.exfil_channel`, with no proto change and no new stage.

## Goals / Non-Goals

**Goals**
- `internal/exfil.Classify(path) Channel` — removable / cloud-sync / local, with configurable roots and
  folder patterns.
- `input.event.exfil_channel` for a filesystem event.
- Prove: path classification and a policy that escalates a sensitive write to an exfil channel.

**Non-Goals**
- Clipboard/print/screenshot producers (OS/display-gated, per-OS follow-ups).
- Content-aware CASB / cloud-provider API integration (folder-name detection here).
- Blocking the write (the policy decides; enforcement is the existing dispatch).

## Decisions

### D1 — Channel is derived from the path in the mapping, no proto change
The channel is a pure function of the resolved path — it carries no content and needs no new field on
the wire. Computing it in `buildInput` (as `behavioral.Analyze` is) keeps the Event contract unchanged
and the derivation content-free. A filesystem event without a resolved path (a raw file handle) yields
an unspecified channel — the classifier only acts on a path it can read.

### D2 — Removable is a mount-root prefix; cloud-sync is a folder-name component
Removable media mounts under well-known roots (`/media`, `/run/media`, `/mnt`) — a path-prefix test.
Cloud-sync folders are identified by a path *component* (`Dropbox`, `OneDrive`, `Google Drive`, `iCloud
Drive`, `Box`, `.dropbox`) so `~/Dropbox/x` and `/home/u/OneDrive/y` both match regardless of the home
prefix. The roots and folder names are configurable (an operator's fleet may mount elsewhere or use a
different sync client), with sensible defaults. Matching is case-insensitive on the component.

### D3 — Local is the explicit default, not an absence
A path that matches no exfil channel is `ChannelLocal`, an explicit value — so a policy reads a concrete
channel for every file event and never has to reason about a missing field. This mirrors the
"no-hidden-default" discipline: the channel is always computed, and "local" is a decision, not a gap.

### D4 — The classifier is content-free and side-effect-free
`Classify` reads only the path string — it never opens the file, stats the filesystem, or resolves
mounts at runtime (which would be a blocking syscall in the decision path, D24). The removable roots are
a static prefix set; if an operator's real mount layout differs they configure the roots. Runtime
mount-table resolution (to catch a removable device mounted at a non-standard path) is a noted follow-up.

## Risks / Trade-offs

- **Folder-name cloud-sync detection** — a folder literally named `Dropbox` that is not a sync folder
  would match (rare, and the operator controls the name set); a renamed sync folder would be missed. A
  content-aware CASB integration is the stronger follow-up, stated.
- **Static removable roots** — a device mounted outside the configured roots is seen as local; runtime
  mount resolution is the follow-up (kept out of the decision path deliberately, D4).

## Migration Plan

Additive: a new package and one derived policy input. No proto, core, or connector change. Existing
policies are unaffected until they consult `input.event.exfil_channel`.

## Open Questions

- Whether to also expose the channel to telemetry (currently only local policy sees it). Deferred; the
  Decision already records the outcome, and the path itself is never in telemetry (D77).
