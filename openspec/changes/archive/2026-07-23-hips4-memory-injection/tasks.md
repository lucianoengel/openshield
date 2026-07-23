## 1. The scanner (`internal/meminject`)

- [x] 1.1 `Region{Start, End uint64, Perms, Path string}`; `parseMaps(r io.Reader) []Region` — parse `/proc/<pid>/maps` lines (`start-end perms offset dev inode pathname`); tolerate malformed lines (skip).
- [x] 1.2 `isWX(perms string) bool` — true iff perms contains both 'w' and 'x'. `SuspectRegions(regions) []Region` — the W+X regions.
- [x] 1.3 `ScanPID(procRoot string, pid int) ([]Region, error)` — read `<procRoot>/<pid>/maps`, return suspect regions. `ExePath(procRoot, pid)` — `readlink <procRoot>/<pid>/exe` (best-effort).
- [x] 1.4 `ScanAll(procRoot string) (map[int][]Region, unreadable int)` — iterate numeric `/proc` entries, `ScanPID` each; skip (count) a pid whose maps can't be read.

## 2. Proto + engine

- [x] 2.1 `proto/openshield/v1/event.proto`: `EVENT_KIND_MEMORY_INJECTION_SUSPECTED = 12`. `make proto`; stage the pb.go before `proto-check`.
- [x] 2.2 (NOT NEEDED — a memory-injection event carries a ProcessSubject, not a path, so the existing fs==nil branch already classifies it metadata-only; adding an explicit case would be dead code. Verified: the engine test passes without any change.) `internal/engine/engine.go` `classifyStage.Run`: add the new kind to the metadata-only switch (do not open the process).

## 3. Producer + wiring (`cmd/openshield-engine`)

- [x] 3.1 `memScanSource(ctx, procRoot, interval, events, log)` — poll `ScanAll`; for each suspect NOT seen before (keyed by pid+exec-path) emit ONE `EVENT_KIND_MEMORY_INJECTION_SUSPECTED` event (ProcessSubject pid + exec path, no memory content); log how many processes were unreadable (privilege hint).
- [x] 3.2 `cmd/openshield-engine/main.go`: behind `OPENSHIELD_MEMSCAN_INTERVAL`, start `memScanSource` on `/proc`. Loud log; inert when unset.

## 4. Tests

- [x] 4.1 `TestParseMapsAndWX` (no root): a synthetic maps blob → parsed; `SuspectRegions` returns ONLY the `rwxp`/`rwxs` lines, not `r-xp`/`rw-p`; a malformed line is skipped.
- [x] 4.2 `TestScanAllSkipsUnreadable` (no root): a fixture `procRoot` tree with a readable maps and a directory whose maps is unreadable/absent → the readable one is scanned, the other counted unreadable, no error.
- [x] 4.3 `TestScanDetectsRealRWX` (real kernel, no root needed for own process): `unix.Mmap(PROT_READ|WRITE|EXEC, MAP_ANON)` a real rwx region in the test process → `ScanPID("/proc", os.Getpid())` includes a W+X region; unmap and (a fresh scan) does not.
- [x] 4.4 `TestMemInjectionAlertsThroughEngine` (real engine + worker): a `MEMORY_INJECTION_SUSPECTED` event → an alert policy → ALERT, and classify does NOT try to read the process.

## 5. Mutation verification

- [x] 5.1 Mutation — `isWX` requires only 'x' (drops the 'w' check): `TestParseMapsAndWX` FAILs (a normal `r-xp` region is now flagged). Revert.
- [x] 5.2 (DROPPED — the classify metadata-only handling for this event comes from the fs==nil branch, not an explicit case; there is no meminject-specific engine code to mutate. The isWX mutation (5.1) is the guard.) Mutation — `classifyStage` does not treat the kind as metadata-only: `TestMemInjectionAlertsThroughEngine` FAILs (classify tries to open the pid path). Revert.

## 6. Gated VM test

- [x] 6.1 A gated real-kernel test (`requireRoot`/skip): run a helper as a DIFFERENT user that maps an rwx region and sleeps, then `ScanPID` its pid AS ROOT → the W+X region is found (the cross-user, root-required fleet-scan path). Build on the VM (`go test -c` + scp + sudo); paste the result. (Locally, a same-uid variant proves the detection; the different-uid case needs the VM.)

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `proto-check` clean; cross-compile clean.
- [x] 7.2 Run the gated VM test; paste the PASS.
- [x] 7.3 decisions.md D-entry; author the new capability spec under `openspec/specs/memory-injection-detection/`; doccheck.
- [x] 7.4 Update the roadmap: HIPS-4 memory/injection detection DONE (W+X scan → alert; JIT allowlist + eBPF real-time deferred) — HIPS-4 subsystems complete. Archive; commit; `git pull --rebase`; push.
