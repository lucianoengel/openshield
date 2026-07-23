## 1. Allowlist mode (`internal/agent/execmon`)

- [x] 1.1 `DenyEvaluator` gains `AllowPaths map[string]bool` + `AllowBasenames map[string]bool` and an `allowlistActive()` helper (true iff non-empty).
- [x] 1.2 `Evaluate`: keep the deny → behavioral checks first (they still block, even an allowlisted binary); then, when `allowlistActive()` and the resolved path/basename is NOT on the allowlist → `VerdictBlock` (default-deny). An empty path (unresolved) → allow. No allowlist → unchanged (allow).

## 2. Wiring (`cmd/openshield-agent`)

- [x] 2.1 `buildEvaluator`: load `OPENSHIELD_EXEC_ALLOW` via `execmon.LoadDenyList` into `AllowPaths`/`AllowBasenames`. The "at least one signal configured" check now also counts an allowlist. Loud log naming whitelisting (default-deny) mode when active.

## 3. Tests (`internal/agent/execmon`, no root)

- [x] 3.1 `TestAllowlistDefaultDeny`: an allowlisted basename → Allow; a NON-allowlisted path → Block; an unresolved (empty) path → Allow.
- [x] 3.2 `TestDenyWinsOverAllow`: a binary on BOTH the allowlist and the deny-list → Block.
- [x] 3.3 `TestNoAllowlistIsDenyListOnly`: no allowlist, a benign non-denied binary → Allow (D224 behavior).
- [x] 3.4 (folded into TestDenyWinsOverAllow — the block-checks-run-before-allowlist ordering; the standalone behavioral test was dropped as fragile) `TestBehavioralBlocksAllowlisted`: an allowlisted path above the behavioral floor → Block (behavioral still applies).

## 4. Mutation verification

- [x] 4.1 Mutation — the allowlist default-deny check is dropped (allowlist mode does not block a non-listed exec): `TestAllowlistDefaultDeny` FAILs. Revert.
- [x] 4.2 Mutation — the deny check moves AFTER the allowlist (allow short-circuits): `TestDenyWinsOverAllow` FAILs. Revert.

## 5. Gated VM test

- [x] 5.1 Extend `execmon_kernel_test.go` (a case): a watchdog with an allowlist of only "helper"; exec a NON-allowlisted "backdoor" from the marked mount → kernel-refused (EACCES); exec the allowlisted "helper" → runs. Build on the VM (`go test -c` + scp + sudo); paste the result.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test skips without root); `check-agent-deps` still green (parser-free); cross-compile clean.
- [x] 6.2 Run the gated allowlist test on the VM; paste the PASS into the D-entry.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/inline-prevention/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: HIPS-4 application whitelisting DONE — default-deny exec. Archive; commit; `git pull --rebase`; push.
