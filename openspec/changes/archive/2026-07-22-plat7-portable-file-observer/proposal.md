## Why

The endpoint engine observes files only on Linux. It opens fanotify directly; on Windows and
macOS every `fanotify.Open` returns `ErrUnsupported`, so `opened == 0` and the engine **exits
at startup** (`errNoWatchDirs`). It cross-compiles for those targets but cannot run. Most
enterprise data lives on Windows and macOS, and ADR-11 / PLAT-7 ratified the route (owner
decision, 2026-07-22): **enforcement** on those platforms is externally gated (Windows EV cert +
attested minifilter; macOS Endpoint Security entitlement — long-lead owner procurement), but
**observation** needs none of that. This change lets the one endpoint agent *run and observe*
on all three operating systems, self-signable and unprivileged, with Linux behavior unchanged.

## What Changes

- New `internal/connectors/filewatch`: a portable, pure-Go, poll-based directory watcher
  (`os.ReadDir` + file metadata snapshot diffing) that detects file creations and modifications
  and produces Events. It exposes the SAME `Open(dir)` / `Next(ctx)` / `Close()` shape as the
  fanotify connector, so the engine uses it interchangeably. Pure standard library — it compiles
  and runs on `linux`, `windows`, and `darwin` with no privilege and no code-signing.
- The engine selects its file watcher **at build time**: `//go:build linux` → fanotify (D52,
  byte-for-byte unchanged), `//go:build !linux` → the portable watcher. `main.go` becomes
  OS-agnostic (calls one `openFileWatcher(dir)` seam and a small `fileWatcher` interface); the
  Linux observe path is preserved exactly. On non-Linux the engine now runs and observes instead
  of exiting.
- Reuses the EXISTING `FilesystemSubject` target and the EXISTING `EVENT_KIND_FILE_CREATED` /
  `EVENT_KIND_FILE_MODIFIED` values — **no proto change, no core change**; a new producer is how
  the fixed pipeline is meant to grow (D26).
- `make all` gains a `GOOS=windows` / `GOOS=darwin` cross-compile check so a portability
  regression fails locally.

### What this change does NOT claim or cover

- **NOT** a second agent or a separate binary. It is the same `openshield-engine`, recompiled
  per-OS with a per-OS watcher. Linux is untouched (fanotify is not even compiled elsewhere).
- **NOT** the native OS file-event APIs (`ReadDirectoryChangesW`, `FSEvents`). Polling is the
  portable baseline; native watchers are a later per-GOOS build-tag optimization on this seam.
- **NOT** enforcement of any kind on Windows/macOS — external-gated (ADR-11), observe only.
- **NOT** the worker's sandbox on non-Linux: the seccomp worker is Linux-specific; on Windows/
  macOS the content parser runs without an OS sandbox until a native sandbox lands (stated
  loudly; the parser boundary as a separate process is preserved, only its confinement weakens).
- **NOT** validated on real Windows/macOS hardware here: those paths cross-compile and the pure
  detection logic is proven on Linux, but their runtime behavior is external-gated for hardware
  validation, stated loudly.
- **NOT** recursive and **NOT** real-time — a poll interval means sub-interval churn is missed.
  The design centre is the careless insider (threat model), not a racing adversary.

## Capabilities

### New Capabilities
- `portable-file-connector`: a cross-platform, poll-based file-observation producer that turns
  file create/modify activity in a watched directory into `FilesystemSubject` Events, runs
  unprivileged on linux/windows/darwin with no OS privilege or code-signing, and exposes the same
  watcher interface the engine already consumes.

### Modified Capabilities
- `endpoint-engine`: the requirement "The engine binary runs the assembled observe pipeline" is
  broadened — the engine opens its file watcher through a per-OS seam (fanotify on Linux, the
  portable watcher elsewhere), so it runs and observes on Windows and macOS instead of exiting.
  Linux behavior is unchanged.

## Impact

- New package `internal/connectors/filewatch` (pure `diff` core + `scan` + `Watcher`).
- `cmd/openshield-engine`: new `watcher_linux.go` / `watcher_other.go` providing
  `openFileWatcher(dir)`, a small `fileWatcher` interface, `watch()` retyped to the interface, and
  a one-line change at the `fanotify.Open` call site. No change to the Linux observe behavior.
- `Makefile`: add windows/darwin cross-compile to the build/all target.
- Dependencies: **none added** — standard library only.
- Depends on D26 (producers extend the pipeline), D52 (the fanotify path this parallels), D48
  (the three-component split, unchanged), D1 (observe-only), D29 (paths not content). Adds a new
  decision recording the portable-observer seam, the non-Linux worker-sandbox gap, and the
  polling/coverage limits.
