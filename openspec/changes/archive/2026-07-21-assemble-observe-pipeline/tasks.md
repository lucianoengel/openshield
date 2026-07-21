# Tasks — assemble the observe pipeline into a running binary

## 1. Wire the engine

- [x] 1.1 `cmd/openshield-engine/main.go`: parse `OPENSHIELD_WATCH_DIRS` (comma-separated); refuse to start with none. Replace `_ = eng` with: one `fanotify.Open(dir)` watcher per dir, a fan-in of `Next(ctx)` events to a single `engine.Process(ctx, ev)` loop; log each Decision. A non-cancellation `Next` error is logged and the watcher continues.
- [x] 1.2 `cmd/openshield-agent/main.go`: message identifies it as the DEFERRED privileged permission-mode (inline-blocking) component (D49), points to `openshield-engine` for observe, exits non-zero.

## 2. Binary-level proof

- [x] 2.1 **Test**: build the actual `openshield-engine` + `openshield-worker` (`go build`), start the engine process with `OPENSHIELD_WATCH_DIRS`=temp dir and `OPENSHIELD_DSN`=test Postgres, write a file with a valid CPF into the watched dir, and poll the ledger for an ALERT entry — asserting the SHIPPED binary runs the path.
- [x] 2.2 **Test**: the engine binary started with no `OPENSHIELD_WATCH_DIRS` exits non-zero (no silent no-op).

## 3. Honesty corrections

- [x] 3.1 README.md: the observe pipeline runs as the `openshield-engine` binary (unprivileged notify-mode fanotify); inline blocking / the privileged agent is deferred (D49). Remove/qualify wording implying the full privileged path ships.
- [x] 3.2 CHANGELOG.md: same correction in the observe-path entry.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D62: the observe pipeline is assembled into the running `openshield-engine` binary (self-watches unprivileged notify-mode, D52); the privileged permission-mode agent is deferred (D49); "runs end to end" is now proven at the binary level, closing audit finding #1.
- [x] 4.2 `openspec validate assemble-observe-pipeline --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| engine drops the no-watch-dirs guard | `TestEngineRefusesNoWatchDirs` |
| engine builds the pipeline but idles (does not Process) | `deploy/observe-e2e.sh` (no ALERT recorded) |

The shipped `openshield-engine` binary now runs the observe path: proven live in
`deploy/observe-e2e.sh` — the real engine+worker binaries watch a dir, classify a
real file with a valid CPF, decide ALERT, and record it in the forward-secure
ledger. A no-watch-dirs start exits non-zero (no silent no-op). Docs corrected:
observe runs as a binary, inline blocking deferred (D49). Audit finding #1 closed.
