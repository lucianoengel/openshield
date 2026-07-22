## 1. Portable watcher — pure detection core

- [x] 1.1 Create `internal/connectors/filewatch/filewatch.go` with `fileState{size, modNano}`, `snapshot` map, `toEvent(dir, name, kind)` → a `FilesystemSubject` Event (ConnectorId `filewatch`, resolved path = `filepath.Join(dir, name)`, no content), and a pure `diff(dir, prev, cur snapshot) []*corev1.Event` returning FILE_CREATED for new paths, FILE_MODIFIED for size-or-modtime changes, nothing for unchanged/deleted.
- [x] 1.2 Unit-test `diff`: new file → CREATED; size change → MODIFIED; modtime-only (same size) change → MODIFIED; unchanged → none; deleted path → none. Assert the produced Event carries the joined path and no content, and only the two existing enum kinds.

## 2. Portable watcher — scan + Open/Next/Close (I/O, Linux-testable)

- [x] 2.1 Add `scan(dir, cap) (snapshot, overflow int, err)` using `os.ReadDir` + `entry.Info()`, regular files only, non-recursive; a file-count cap with a loud+counted overflow (never silent truncation).
- [x] 2.2 Add `Watcher` with `Open(dir)` (prime a silent baseline via the first `scan`), `Next(ctx) (*corev1.Event, error)` (return one buffered event per call; when the buffer drains, sleep the interval racing `ctx.Done()`, `scan`, `diff` vs baseline, advance baseline; return `ctx.Err()` on cancel), and `Close()`. Defaults: interval ~2s, cap ~10k.
- [x] 2.3 Test against a real temp dir: pre-existing file does NOT fire at startup (priming); a file created after start fires CREATED; a modification fires MODIFIED; several changes in one scan return one-at-a-time via successive `Next`; a cancelled ctx makes `Next` return; overflow counter increments past the cap.

## 3. Engine per-OS watcher seam (Linux behavior unchanged)

- [x] 3.1 Add a `fileWatcher` interface `{ Next(context.Context) (*corev1.Event, error); Close() error }` and `openFileWatcher(dir string) (fileWatcher, error)` in `cmd/openshield-engine`, split `watcher_linux.go` (`//go:build linux` → `fanotify.Open`) and `watcher_other.go` (`//go:build !linux` → `filewatch.Open`).
- [x] 3.2 Retype `watch(...)` to take `fileWatcher` and change the `main.go` call site from `fanotify.Open(dir)` to `openFileWatcher(dir)`; confirm no other behavior changes (still validates dirs, still fatal on `opened == 0`, still observe-only).
- [x] 3.3 Confirm the Linux engine still builds and its existing binary/observe tests pass unchanged (fanotify path intact).

## 4. Cross-platform build proof

- [x] 4.1 Verify `GOOS=windows go build ./...` and `GOOS=darwin go build ./...` succeed with the new package + engine seam included; fix any non-portable calls.
- [x] 4.2 Add a `cross-compile` check (windows+darwin build of `./...`) to the `Makefile` build/all target so a portability regression fails locally.

## 5. Mutation testing + verification

- [x] 5.1 Ran each planned mutation — all Linux-runnable ones CAUGHT: (a) `diff` skips new files → CREATED test failed ✓; (b) `diff` ignores modtime (size-only) → same-size-modtime test failed ✓; (c) `diff` over-emits (unchanged fires) → unchanged test failed ✓; (d) `Open` empty baseline (priming broken) → silent-priming test failed ✓; (e) overflow not counted → overflow test failed ✓. (f) `openFileWatcher` on non-linux wired to fanotify (ErrUnsupported) → guarded by `watcher_other_test.go` (`//go:build !linux`); EXTERNAL-GATED for execution on the Linux CI (runs on a Mac/Windows host), compile-verified here via `GOOS=darwin/windows go vet`.
- [x] 5.2 Run `make all` (build incl. cross-compile, `-race ./...`, doccheck, boundary/fitness guards) and confirm green.

## 6. Decision + docs

- [x] 6.1 Add the next decision to `docs/decisions.md`: the per-OS engine watcher seam (fanotify on Linux unchanged, portable poll watcher elsewhere), the non-Linux worker-sandbox gap, and the polling/coverage limits; reference D26/D48/D52/D1/D29 and ADR-11/PLAT-7.
- [x] 6.2 Update `docs/architecture-roadmap.md` PLAT-7 status to reflect the shipped cross-platform observe path (builder-half increment done; native watchers, non-Linux worker sandbox, and clipboard/print remain follow-ups).
- [x] 6.3 `openspec validate plat7-portable-file-observer --strict`, then archive via the openspec-archive-change skill and fix the archived spec's Purpose line.
