## Context

The endpoint agent observes files only on Linux. `cmd/openshield-engine/main.go` opens the
fanotify connector directly (`fanotify.Open(dir)`); the connector has a `//go:build !linux` stub
(`watch_other.go`) returning `ErrUnsupported`, so on Windows/macOS every open fails, `opened == 0`,
and the engine calls `fatal(...errNoWatchDirs)` — it cross-compiles but cannot run. ADR-11 / PLAT-7
splits cross-platform work into owner-gated **enforcement** and builder-ready **observation**; this
lands observation by giving the engine a working, unprivileged watcher on every OS.

The endpoint remains the same three components (D48): privileged (deferred) blocker, unprivileged
engine, sandboxed worker. This change touches only *which file watcher the engine opens*, per OS.

## Goals / Non-Goals

**Goals:**
- The one `openshield-engine` runs and observes on linux/windows/darwin, unprivileged,
  self-signable (no EV cert, no notarization, no kernel driver).
- Linux observe path byte-for-byte unchanged (still fanotify; the portable watcher is not
  compiled on Linux).
- Zero proto/core change: reuse `FilesystemSubject` + `EVENT_KIND_FILE_CREATED/MODIFIED`.
- A pure, mutation-tested detection core; watcher + engine seam tested on Linux; windows/darwin
  proven to compile.

**Non-Goals:**
- Native OS watch APIs (`ReadDirectoryChangesW`, `FSEvents`) — a later build-tag optimization.
- Enforcement on any OS — external-gated (ADR-11).
- The worker's OS sandbox on non-Linux — seccomp is Linux-specific; the parser stays a separate
  process but runs unconfined on Windows/macOS until a native sandbox lands (stated, follow-up).
- Running/validating the Windows/macOS runtime here — cross-compile + Linux-run only.

## Decisions

**D — Per-OS watcher chosen by a build-time seam, not a runtime branch.**
Add `cmd/openshield-engine/watcher_linux.go` (`//go:build linux`) and `watcher_other.go`
(`//go:build !linux`), each providing `func openFileWatcher(dir string) (fileWatcher, error)` where
`fileWatcher` is a tiny local interface `{ Next(context.Context) (*corev1.Event, error); Close() error }`.
`main.go` calls `openFileWatcher(dir)` instead of `fanotify.Open(dir)`, and `watch()` takes the
interface. Linux returns a fanotify watcher (unchanged behavior); non-Linux returns the portable
watcher. `main.go` holds no OS-specific code.
- *Alternative: a runtime `if runtime.GOOS == ...`.* Rejected: it would compile fanotify into every
  target (it already stubs out, but the intent is clearer as a build seam) and reads as a special
  case rather than a clean per-OS provider. Build tags match the existing fanotify split.

**D — Portable watcher = poll + snapshot-diff, pure stdlib, no new dependency.**
`internal/connectors/filewatch` scans the directory each interval (`os.ReadDir` + `entry.Info()`),
builds a snapshot `map[name]{size, modUnixNano}`, and diffs against the previous snapshot. Pure
standard library ⇒ identical code on all three GOOS, and it *runs* on Linux so it is fully testable
here.
- *Alternative: `github.com/fsnotify/fsnotify`.* Rejected for v1: adds a dependency (deps kept
  minimal — prior OSS DLP died of maintenance economics), and its Windows/macOS backends still
  cannot be exercised here, so it would not improve test honesty. It is the natural native-watcher
  follow-up on this seam.
- *Alternative: hand-written per-GOOS native watchers now.* Rejected: mostly Windows/darwin syscall
  bindings that cross-compile but cannot be run or tested here — the "verifies against its own
  assumptions" trap. Polling is honest: what the test exercises is what ships.

**D — Same `Open/Next/Close` shape as fanotify.** `filewatch.Open(dir)` primes a silent baseline;
`Next(ctx)` returns one buffered Event per call, scanning again when the buffer drains, and returns
`ctx.Err()` on cancel; `Close()` releases. This lets the engine consume it exactly like the fanotify
watcher through the `fileWatcher` interface — no pipeline change.

**D — Split pure `diff` from I/O `scan`/`Next` (the fanotify `ParseEvent` discipline).**
`diff(dir, prev, cur) []*Event` is pure and carries the detection logic and the mutation surface.
`scan(dir, cap)` does the filesystem read with a file-count cap (loud, counted overflow — no silent
truncation). Silent baseline priming lives in `Open`/`Next`, not `diff` (which is stateless), and
gets its own test + mutation because startup-flood is the classic bug.

**D — Modification = size OR modtime change.** Size alone misses same-length edits; size+modtime is
the standard portable heuristic. A dedicated same-size-newer-modtime test isolates the modtime guard.
Best-effort, not adversary-proof (threat model: careless insider).

**D — Cross-compile check in `make`.** Add `GOOS=windows go build ./...` and `GOOS=darwin go build
./...` to the build/all target so a Windows/darwin-breaking edit fails locally (the gate is local
`make all`, not CI polling).

## Risks / Trade-offs

- **[Sub-interval churn is missed]** A create-then-delete inside one poll interval never appears.
  → Accepted and documented; design centre is the careless insider. Native watchers (follow-up)
  close this where the OS supports it.
- **[Polling cost on large trees]** → non-recursive single directory + file-count cap + a sane
  default interval bound the cost; operators pick the directories. Recursion is a deliberate
  follow-up.
- **[Worker unsandboxed on non-Linux]** seccomp is Linux-only, so on Windows/macOS the content
  parser runs without an OS sandbox. → Stated loudly in the proposal + decision; the parser stays a
  separate process (the boundary holds), only its confinement weakens until a native sandbox lands.
  This is an observation-tier honesty caveat, not a silent regression.
- **[Windows/macOS runtime unverified here]** cross-compile passes and the pure logic is Linux-
  proven, but behavior on those OSes is untested. → Stated as external-gated; the watcher is pure
  `os.ReadDir`/`Stat`, so portability risk is low.
- **[modtime granularity / clock skew]** → size-OR-modtime reduces misses; a double-count yields a
  redundant MODIFIED Event, harmless (observe-only, idempotent downstream classify).

## Migration Plan

Additive and behavior-preserving on Linux. New package + two build-tagged engine files + a retyped
`watch()` + a one-line call-site change + a Makefile check. No migrations, no proto regen, no
dependency, no change to the Linux observe behavior or any other spec. Rollback = revert the commit;
on Linux nothing changes regardless.

## Open Questions

- Default poll interval and file-count cap — pick sensible defaults now (interval ~2s, cap ~10k),
  make the interval env-tunable later if operators ask.
- Native watchers as `fsnotify` vs hand-written per-GOOS — defer to the follow-up; this change only
  establishes the seam and the reusable pure core.
- The non-Linux worker sandbox (Windows job objects / AppContainer, macOS sandbox) — a separate
  follow-up; out of scope here.
