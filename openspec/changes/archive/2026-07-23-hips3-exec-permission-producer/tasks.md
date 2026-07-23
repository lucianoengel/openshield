## 1. Refactor: detaint the watchdog package

- [x] 1.1 Move `ExecDecider` + `ExecEvaluator` from `internal/agent/watchdog/execeval.go` to `internal/agent/execguard/` (a new `execeval.go` there), rewriting `watchdog.Verdict`/`watchdog.PermissionEvent` references as needed (execguard imports watchdog).
- [x] 1.2 Delete `internal/agent/watchdog/execeval.go` (and move its test `execeval_test.go` → execguard, updating `watchdog.ExecEvaluator` → `execguard.ExecEvaluator`).
- [x] 1.3 Verify: `go list -deps ./internal/agent/watchdog | grep encoding/json` is EMPTY (watchdog is now parser-free).

## 2. The fanotify exec-permission producer (`internal/agent/execmon`)

- [x] 2.1 `execmon_linux.go` (`//go:build linux`): `Open(paths []string) (*Monitor, error)` — `FanotifyInit(FAN_CLASS_CONTENT|FAN_CLOEXEC, O_RDONLY)`, `FanotifyMark(FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, AT_FDCWD, path)` per path; store the group fd. `NotifyFD()` accessor for the `FanotifyResponder`.
- [x] 2.2 `Run(ctx, wd *watchdog.Watchdog) error`: loop `unix.Read` the group fd; for each `unix.FanotifyEventMetadata` in the buffer build `watchdog.PermissionEvent{PID, FD, Path: readlink(/proc/self/fd/<fd>)}`, call `wd.Handle`, then `unix.Close(FD)`. A short/version-mismatched record → answer ALLOW via the responder + close + continue (never hang). Respect `ctx` for shutdown.
- [x] 2.3 `decodeMeta(buf []byte) (meta, rest, ok)` — a PURE decoder over the 24-byte struct (unit-testable, no root); a truncated buffer returns `ok=false`, never panics.
- [x] 2.4 `execmon_other.go` (`//go:build !linux`): a stub so the tree cross-compiles (Open returns an unsupported error).

## 3. Pure inline exec evaluator

- [x] 3.1 `denyeval.go` (no build tag, no corev1): `DenyEvaluator{ DenyPaths map[string]bool, DenyBasenames map[string]bool, BehaviorThreshold float64 }` implementing `watchdog.Evaluator`: `Evaluate` reads `e.Path`, returns `VerdictBlock` on a deny-list hit or `behavioral.Analyze(path, "", nil).Score >= threshold` (when threshold>0), else `VerdictAllow`. Never errors (a pure decision). `LoadDenyList(path)` parses a newline/`#`-comment file of exec paths/basenames.

## 4. Wire into the privileged agent

- [x] 4.1 `cmd/openshield-agent/main.go`: if `OPENSHIELD_EXEC_MONITOR_DIRS` is set, `execmon.Open` the dirs, build `watchdog.Watchdog{Evaluator: DenyEvaluator (from OPENSHIELD_EXEC_DENY + OPENSHIELD_EXEC_BEHAVIOR_THRESHOLD), Responder: FanotifyResponder{NotifyFD}, SelfPID: int32(os.Getpid()), Budget, Audit: a stderr logger}`, and `Run`. Keep the non-zero-exit stub when unset.
- [x] 4.2 `scripts/check-agent-deps.sh` (or `make check`) passes — the privileged binary pulls no `encoding/json`/parser (execmon + watchdog + behavioral only). Verify explicitly.

## 5. Tests

- [x] 5.1 `decodeMeta` unit test (NO root): a synthetic 24-byte metadata → decoded PID/FD/Mask/len; a 10-byte truncation → `ok=false`, no panic; two concatenated records → both decoded.
- [x] 5.2 `DenyEvaluator` unit tests (NO root): a deny-listed basename → VerdictBlock; a deny-listed absolute path → Block; a benign path → Allow; a high-behavioral exec path (e.g. an encoded-powershell arg pattern) over the threshold → Block; `LoadDenyList` parse + comments.
- [x] 5.3 GATED real-kernel integration test `execmon_kernel_test.go` (`requireExecPerm(t)`: skip unless linux + `os.Geteuid()==0` + a probe `FanotifyInit(FAN_CLASS_CONTENT)` succeeds): mark a temp dir, deny a copied binary by basename, run the monitor in a goroutine, exec the denied binary from the dir → `exec` returns EACCES/EPERM (blocked); a benign copied binary in the same dir → runs (exit 0). Assert `/proc/self/fd` count does not grow across N execs (no fd leak).

## 6. Mutation verification

- [x] 6.1 Mutation — `DenyEvaluator` drops the deny-list check (always Allow): `TestDenyEvaluatorBlocks` FAILs. Revert.
- [x] 6.2 Mutation — `decodeMeta` ignores the length check (returns ok on a truncated buffer): the truncation test FAILs. Revert.
- [x] 6.3 Mutation (kernel, on the VM) — the producer answers FAN_ALLOW for a Block verdict: the gated test's denied exec RUNS → FAILs. Revert.

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green locally (the gated kernel test SKIPS without root, like swtpm); `make check`/`check-agent-deps` green.
- [x] 7.2 Build the gated test on the VM: `go test -c ./internal/agent/execmon` locally → `scp` the binary to `coder@192.168.122.83` → `sudo ./execmon.test -test.run Kernel -test.v`; paste the PASS output into the D-entry.
- [x] 7.3 decisions.md D-entry (record the parser-free/json refactor finding); sync the delta into `openspec/specs/inline-prevention/spec.md`; doccheck.
- [x] 7.4 Update the roadmap: HIPS-3 exec-permission producer DONE (inline exec prevention real on a live kernel; increment-1 pure decider; full-policy-inline = increment 2 via IPC). Archive; commit; `git pull --rebase`; push.
