## 1. The supervisor (`internal/gateway`)

- [x] 1.1 `superviseTProxy(ctx, arm func(ctx) error, backoff func(ctx) bool, log)` — loop: exit on ctx; call arm (blocks while serving); on return re-arm after backoff; backoff returns false on ctx-cancel-during-wait → exit. Log arm errors + the re-arm.
- [x] 1.2 `sleepCtx(ctx, d) bool` — sleep d or until ctx done; false if ctx done. Exported `SuperviseTProxy(ctx, addr, dports, mark, table, retry, newServer func() *TProxyServer, log)` builds arm from `ListenTransparent` + `RunTProxyWithRules(newServer())` (fresh listener each arm) and backoff from `sleepCtx`. A small `listenerPort(ln, addr)` helper for the bound port.

## 2. Wiring (`cmd/openshield-gateway`)

- [x] 2.1 `applyTProxy` self-install path: replace `go RunTProxyWithRules(ctx, ln, srv, …)` (listener created once up front) with `go gateway.SuperviseTProxy(ctx, addr, dports, mark, table, backoff, newServer, log)` — the supervisor owns listener creation. Drop the up-front listener for that path (a bind failure is now retried, not fatal). Backoff from `OPENSHIELD_TPROXY_RETRY` (default 5s). Operator-owns-rules path unchanged (one-shot serve).

## 3. Tests

- [x] 3.1 (no root) `superviseTProxy` with fakes: arm returns immediately each time, backoff cancels the ctx after N iterations → arm called N times, loop exits on ctx (self-heal retries then stops); backoff-returns-false exits promptly; ctx already cancelled → arm never called.

## 4. Mutation verification

- [x] 4.1 (no root) The loop returns after the first arm (no re-loop) → arm called once → the "retried N times" assertion FAILs. Revert.

## 5. Gated VM test

- [x] 5.1 Reuse the netns topology; drive `superviseTProxy` with a real arm that creates a transparent listener, publishes it on a channel, then runs `RunTProxyWithRules`. Read listener #1 → a forwarded flow splices (plane up); CLOSE listener #1 → the supervisor re-arms → read listener #2 → a forwarded flow splices AGAIN (self-healed). Cancel ctx. Build on the VM; paste the PASS.

## 6. Mutation (gated VM)

- [x] 6.1 The loop exits after the first arm → listener #2 never appears → the VM test blocks and FAILs on timeout. Revert.

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test SKIPS without root); proto-check clean; cross-compile clean.
- [x] 7.2 Run the gated VM test; paste the PASS + the mutation FAIL.
- [x] 7.3 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 7.4 Update the roadmap: NIPS-1 increment 4c (self-heal) DONE; note remaining deferrals (operator-path self-heal, circuit breaker, hung-listener probe, nft-native). Archive; commit; `git pull --rebase`; push.
