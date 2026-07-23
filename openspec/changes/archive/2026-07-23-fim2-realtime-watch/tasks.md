## 1. Real-time FIM source (`cmd/openshield-engine/fimwatch.go`)

- [x] 1.1 `fimWatchDirs(paths []string) []string` — the deduped set of directories to watch: a file path → its parent dir, a directory path → itself.
- [x] 1.2 `fimWatchSource(ctx, m *fim.Manifest, paths []string, opts fim.Options, debounce time.Duration, events chan<- *corev1.Event, log)` — open a `fanotify.Open` watcher per watch-dir (log + skip a dir that can't open — fail-to-wire); fan each watcher's `Next` events into one trigger channel (coalesced); on a trigger, wait the debounce window draining further triggers, then `fim.Scan(m, paths, opts)` and emit each drift via `fimEvent`. Respect `ctx`.

## 2. Wiring

- [x] 2.1 `cmd/openshield-engine/main.go`: when FIM is configured AND `OPENSHIELD_FIM_REALTIME` is set, start `fimWatchSource` (wg-tracked) alongside the existing poll `fimSource`. Loud log; a watch that can't arm degrades to poll-only.

## 3. Tests

- [x] 3.1 `TestFimWatchDirs`: a file path → its parent; a dir path → itself; dedup.
- [x] 3.2 `TestFimRealtimeDetectsModify` (gated `requireFanotify`: skip if unprivileged `fanotify.Open` fails): build a baseline for a temp dir, start `fimWatchSource` with a LONG poll-irrelevant setup (this source has no poll — the test asserts real-time), modify a baselined file (content change), and assert a `FILE_MODIFIED` drift event arrives on the channel within ~2s (well under a realistic poll interval). A timestomped edit (restored mtime, same size) is still detected (the hash).
- [x] 3.3 `TestFimRealtimeNoDriftOnNoChange` (gated): touch a watched file WITHOUT changing content (rewrite identical bytes) → after the debounce, NO drift event (the baseline scan confirms, not the raw event).

## 4. Mutation verification

- [x] 4.1 Mutation — `fimWatchSource` emits a drift on the raw event WITHOUT running `fim.Scan` (trusts the event): `TestFimRealtimeNoDriftOnNoChange` FAILs (a no-content-change event now false-drifts). Revert.
- [x] 4.2 Mutation — the trigger loop never scans (drops the trigger): `TestFimRealtimeDetectsModify` FAILs (no drift within the deadline). Revert.

## 5. Gate & land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (the gated test SKIPS where fanotify is unavailable); cross-compile clean.
- [x] 5.2 decisions.md D-entry; sync the delta into `openspec/specs/file-integrity-monitoring/spec.md`; doccheck.
- [x] 5.3 Update the roadmap: FIM real-time (increment 2) DONE — tamper detected in ~ms, poll is the backstop. Archive; commit; `git pull --rebase`; push.
