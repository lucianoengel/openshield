## Why

OpenShield observes files being written, but it treats a write to a personal scratch folder and a write
to a synced cloud folder or a removable drive identically. Yet the whole point of DLP is the *channel*:
sensitive content landing in `~/Dropbox` or on a USB stick is exfiltration; the same content in a temp
dir is not. "A DLP that watches directories but not the channels users exfiltrate through is not a DLP"
(DLP-2). This makes the file-observe path **channel-aware**: it classifies which exfil channel a file
event is on, so a policy can escalate on "sensitive data → an exfil channel" without touching content.

## What Changes

- An `internal/exfil` classifier: given a file path, determine the exfil channel — removable media
  (under a mount root like `/media`, `/run/media`, `/mnt`) or a cloud-sync folder (Dropbox, OneDrive,
  Google Drive, iCloud, Box), else local.
- The policy input exposes `input.event.exfil_channel` for a filesystem event, computed from the
  resolved path — a pure, content-free derivation, exactly like the behavioral analysis already computed
  in the mapping. So a policy can treat a sensitive write to a cloud-sync/removable channel differently
  from a local one.

## Capabilities

### New Capabilities
- `exfil-channel-awareness`: classify which exfiltration channel a file event is on (removable media,
  cloud-sync, local) so the policy can act on the channel, not only the content — the pipeline
  foundation for channel-aware DLP.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** a new `internal/exfil` package (path → channel, with configurable roots); `exfil_channel`
  exposed in the policy input for filesystem events. No proto change — the channel is derived from the
  path, content-free, like `input.event.behavioral`. Proven: path classification (removable roots,
  cloud-sync folder patterns, local default, edge cases); a policy escalates a sensitive write to a
  cloud-sync/removable channel and not the same write locally.
- **Scope note (honest):** this covers the **file-based** exfil channels (removable-media file-copy and
  cloud-sync folders), which flow through the existing fanotify/filewatch producers pointed at those
  paths. The **non-file channels** — clipboard, print spooler, screenshot — need OS/display-server
  producers (X11/Wayland, CUPS, per-OS capture APIs) that this rootless headless environment cannot
  validate; they are per-OS producer follow-ups (like NIPS-1's root-gated data plane). The cloud-sync
  detection is folder-name based; a **content-aware CASB / cloud API** integration is a larger follow-up.
