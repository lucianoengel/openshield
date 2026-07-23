## 1. The lifecycle helper (`internal/gateway`)

- [x] 1.1 `runTProxyWithRules(ctx, serve func(ctx) error, install func() error, remove func(), log)` — install; run serve (blocks); remove ONLY if install succeeded, on EVERY serve return (not just ctx cancel); log an unexpected stop (serve err with ctx still live).
- [x] 1.2 Exported `RunTProxyWithRules(ctx, ln net.Listener, srv *TProxyServer, port int, dports []int, mark, table int, log)` wrapping the core with real `InstallTProxyRules`/`RemoveTProxyRules`/`srv.Serve`.

## 2. Wiring (`cmd/openshield-gateway`)

- [x] 2.1 In `applyTProxy`, the self-install path (`OPENSHIELD_TPROXY_INSTALL_RULES=1`): replace the separate Serve goroutine + remove-on-`ctx.Done()` pair with `go gateway.RunTProxyWithRules(...)`. The operator-owns-rules path is unchanged (plain `go srv.Serve`). Keep the port==0 fallback (serve without self-installed rules).

## 3. Tests

- [x] 3.1 (no root) `runTProxyWithRules` with fakes: `serve` returns an error with ctx live → `remove` called exactly once; `install` fails → `remove` NOT called; ctx-cancel serve-return → `remove` called.

## 4. Mutation verification

- [x] 4.1 (no root) Bind remove to `ctx.Done()` instead of the serve-return → a serve that returns before ctx cancel leaves `remove` uncalled → the 3.1 "remove on server stop" assertion FAILs. Revert.
- [x] 4.2 (no root) Remove is called even when install failed → the "install-fails → no remove" assertion FAILs. Revert.

## 5. Gated VM test

- [x] 5.1 Reuse the netns topology: run `RunTProxyWithRules` in a goroutine over a real transparent listener + self-installed rules; assert a forwarded flow is spliced (rules active). Then CLOSE the listener (server stops) with ctx still live; assert the TPROXY rule is GONE (`iptables -t mangle -C …` non-zero) — removed on server stop, not left dangling. Build on the VM; paste the PASS.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test SKIPS without root); proto-check clean; cross-compile clean.
- [x] 6.2 Run the gated VM test; paste the PASS.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: NIPS-1 increment 4b (rule lifecycle bound to server) DONE; note the self-heal restart still deferred. Archive; commit; `git pull --rebase`; push.
