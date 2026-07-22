# Tasks

## 1. Exfil-channel classifier
- [x] 1.1 `internal/exfil/exfil.go`: `Channel` (`ChannelLocal`, `ChannelRemovable`, `ChannelCloudSync`)
  with a `String()`; a default `Classifier` with removable roots (`/media`, `/run/media`, `/mnt`) and
  cloud-sync folder names (`Dropbox`, `OneDrive`, `Google Drive`, `iCloud Drive`, `Box`, `.dropbox`);
  `Classify(path) Channel` = removable root prefix, else a cloud-sync path-component (case-insensitive),
  else local. Content-free, no filesystem access. Configurable roots/names via a constructor.

## 2. Policy input
- [x] 2.1 `policy.buildInput`: for a filesystem event with a resolved path, expose
  `input.event.exfil_channel` = `exfil.Classify(path).String()` (a content-free derivation, like
  `input.event.behavioral`). Absent for a non-filesystem event or a handle-only filesystem event.

## 3. Tests
- [x] 3.1 Classifier units: `/media/usb0/x` and `/run/media/u/d/x` → removable; `/home/u/Dropbox/x`,
  `~/OneDrive/y`, `/x/Google Drive/z` → cloud-sync (case-insensitive); `/home/u/docs/x`, `/tmp/x` →
  local; empty path → local; a folder merely CONTAINING "dropbox" as a substring of a larger name
  (`dropboxes`) → local (component match, not substring); a custom-configured root/name works.
- [x] 3.2 Policy integration (real rego + dispatcher): a filesystem event carrying a sensitive
  classification with a cloud-sync path → the policy escalates (BLOCK); the SAME classification with a
  local path → does not escalate (ALERT/ALLOW); `input.event.exfil_channel` reflects the path.

## 4. Mutation guards
- [x] 4.1 Make cloud-sync matching a plain substring (not a path-component) → the `dropboxes` case (3.1)
  FAILs (a non-sync folder matches). Revert.
- [x] 4.2 Make `buildInput` not set `exfil_channel` (drop it) → the policy-escalation test (3.2) FAILs
  (the policy can't see the channel, does not escalate). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D194) — DLP-2 exfil-channel awareness (file-based channels);
  path-derived content-free; local is explicit; clipboard/print/screenshot producers + CASB are per-OS
  follow-ups; runtime mount resolution deferred (kept out of the decision path).
- [x] 5.2 `docs/architecture-roadmap.md`: mark DLP-2 channel-awareness (file-based) shipped; note the
  per-OS producers remaining.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/exfil-channel-awareness/spec.md`.
