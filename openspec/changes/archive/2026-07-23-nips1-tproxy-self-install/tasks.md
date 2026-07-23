## 1. The rule installer (`internal/gateway/tproxyrules.go`)

- [x] 1.1 Pure arg builders (portable, no root): `tproxyInstallArgs(listenPort int, dports []int, mark, table int) (ip, ipt [][]string)` — the `ip rule add fwmark <mark> lookup <table>` + `ip route add local 0.0.0.0/0 dev lo table <table>`; the mangle chain `OPENSHIELD_TPROXY` scaffold + a per-dport TPROXY rule (`--on-port <listen> --tproxy-mark <mark>`) + the `PREROUTING` jump. `tproxyRemoveArgs(mark, table)` — the inverse (rule del, route flush table, jump -D, chain -F/-X).
- [x] 1.2 `tproxyrules_linux.go`: `InstallTProxyRules(listenPort int, dports []int, mark, table int) error` (best-effort teardown+scaffold, fatal rule-adds, prefer iptables+ip, remove-then-add idempotent); `RemoveTProxyRules(mark, table int) error` (idempotent). Loud logging.
- [x] 1.3 `tproxyrules_other.go` (`!linux`): both return a clear "linux-only" error.

## 2. Wiring (`cmd/openshield-gateway`)

- [x] 2.1 In `applyTProxy`, behind `OPENSHIELD_TPROXY_INSTALL_RULES=1`: after the listener arms, parse the listen port + `OPENSHIELD_TPROXY_DPORTS` (default `80,443`), mark (`OPENSHIELD_TPROXY_MARK`, default 1), table (`OPENSHIELD_TPROXY_TABLE`, default 100); `InstallTProxyRules(...)` on startup, `RemoveTProxyRules(...)` on `ctx.Done()`. An install failure logs loudly and the plane keeps running (never fail-closed).

## 3. Tests

- [x] 3.1 (no root) The arg builders: the `ip` sequence carries the fwmark rule + the divert route in the dedicated table; the iptables sequence carries a per-dport TPROXY rule (`--on-port`, `--tproxy-mark`) in the dedicated chain + the PREROUTING jump; Remove is the inverse and never flushes PREROUTING or the main table; the `!linux` stub errors clearly.

## 4. Gated VM test

- [x] 4.1 Reuse the netns+veth topology from `tproxy_kernel_test`, but install the TPROXY plumbing via `InstallTProxyRules` instead of the manual rule lines: a flow from the namespace to a BLOCKED dst is DROPPED, to an ALLOWED dst is SPLICED — proving the self-installed rules deliver flows to the transparent listener. `RemoveTProxyRules` cleans up. Build on the VM (`go test -c`+scp+`sudo`); paste the PASS.

## 5. Mutation verification

- [x] 5.1 (gated, VM) Drop the divert `ip route`/`ip rule` (routing half) from `InstallTProxyRules` → a marked packet is not delivered locally → the allowed flow never reaches the listener → the splice times out → the VM test FAILs. Revert.
- [x] 5.2 (no root) An arg-builder mutation the unit test catches: Remove omits the dedicated-chain teardown (or the route flush) → the "Remove is the inverse" assertion FAILs. Revert.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test SKIPS without root); proto-check clean; cross-compile clean (`!linux` stub).
- [x] 6.2 Run the gated VM test; paste the PASS + the mutation FAIL.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: NIPS-1 increment 4a (self-installing TPROXY rules) DONE; note deferred (nft-native, bypass watchdog, OUTPUT/local-host case, IPv6). Archive; commit; `git pull --rebase`; push.
