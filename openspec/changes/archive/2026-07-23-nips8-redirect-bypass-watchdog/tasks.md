## 1. The watchdog (`internal/dnsredirect`)

- [x] 1.1 `Watchdog{Port, Mark int; Interval time.Duration; Failures int; Probe func() bool; Log *slog.Logger}` plus unexported `install func() error`, `remove func()` test-indirection fields (nil → the real `Install`/`Remove`). Defaults: Interval 5s, Failures 3.
- [x] 1.2 Extract the per-tick transition into `step()` (probe → update `consecutiveFailures`/`installed`, bypass on threshold, restore on recovery) so the state machine is testable without real time. `Run(ctx)` installs, then drives `step()` on a ticker until `ctx.Done()`, then `remove()`.
- [x] 1.3 `defaultProbe(port int) func() bool`: dial `127.0.0.1:port` UDP, send a well-formed query for a fixed innocuous name, return true iff any response arrives within a short timeout. Used when `Probe` is nil.

## 2. Wiring (`cmd/openshield-gateway`)

- [x] 2.1 In `applyDNSSink`, when `OPENSHIELD_DNS_REDIRECT=1`, run `(&dnsredirect.Watchdog{Port, Mark, Log}).Run(ctx)` in a goroutine instead of the bare `Install` + `Remove-on-ctx`. The Watchdog owns install/remove and the install-failure-keep-running behavior.

## 3. Tests

- [x] 3.1 (no root) State-machine unit test with fake `probe`/`install`/`remove` hooks, driving `step()` directly: `Failures=3` → two failing steps do NOT remove, the third removes exactly once; after bypass a passing step re-installs exactly once and resets the counter; a `Run` with a cancelled ctx removes. Assert install/remove call counts.
- [x] 3.2 (no root) `defaultProbe` against a live stub resolver returns true; against a closed port returns false within the timeout.

## 4. Mutation verification

- [x] 4.1 (no root) `step()` bypasses after 1 failure instead of `Failures` (threshold off-by-one) → the "two failures do not remove" assertion in 3.1 FAILs. Revert.
- [x] 4.2 (no root) `step()` never resets `consecutiveFailures` on a passing probe → a fail,fail,pass,fail sequence wrongly bypasses → a "does not bypass on intermittent failures" assertion FAILs. Revert.

## 5. Gated VM test

- [x] 5.1 A gated real-kernel test (`requireRoot`+linux, else skip), self-contained on loopback: a canned upstream on `127.0.0.2:53`; a real sinkhole resolver blocking `evil.example` behind a real `Watchdog` (short interval); `evil.example` → NXDOMAIN (redirect active). Then KILL the resolver; after the bypass fires, `evil.example` reaches the real `127.0.0.2:53` upstream directly → NOERROR (sinkhole bypassed, resolution NOT wedged). Cancel `Run`; the redirect is gone. Build on the VM (`go test -c`+scp+`sudo`); paste the PASS.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test SKIPS without root); proto-check clean; cross-compile clean.
- [x] 6.2 Run the gated VM test; paste the PASS.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/dns-sinkhole/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: NIPS-8 increment 3 (redirect bypass watchdog) DONE; note deferred (TPROXY watchdog, backoff/hold-down, bypass alert, upstream-independent sentinel probe). Archive; commit; `git pull --rebase`; push.
