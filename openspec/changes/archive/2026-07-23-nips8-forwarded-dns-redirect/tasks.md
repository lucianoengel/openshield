## 1. Forwarded redirect (`internal/dnsredirect`)

- [x] 1.1 Pure arg builders (portable): `iptablesForwardedInstallArgs(port)` — a REDIRECT rule in a dedicated chain `OPENSHIELD_DNSREDIR_FWD` (`! -i lo -p udp --dport 53 -j REDIRECT --to-ports <port>`, NO mark) + a PREROUTING jump; `iptablesForwardedScaffoldArgs()`; `iptablesForwardedRemoveArgs()` (inverse: -D PREROUTING jump, -F, -X the fwd chain).
- [x] 1.2 `InstallForwarded(port int, log) error` / `RemoveForwarded(log) error` in `dnsredirect_linux.go` (iptables; remove-then-add idempotent). `_other.go` stubs return `errUnsupported`/nil.

## 2. Watchdog scope (`internal/dnsredirect`)

- [x] 2.1 `type Scope int` with `ScopeLocal`(0)/`ScopeForwarded`/`ScopeBoth`. Add `Scope Scope` to `Watchdog`. `doInstall`: install local when scope includes local, forwarded when it includes forwarded (both on ScopeBoth); `doRemove`: tear down both best-effort. Default (ScopeLocal) unchanged.

## 3. Wiring (`cmd/openshield-gateway`)

- [x] 3.1 `applyDNSSink`: parse `OPENSHIELD_DNS_REDIRECT` = `1`/`local`→ScopeLocal, `forwarded`→ScopeForwarded, `both`→ScopeBoth; set `Watchdog.Scope`. Mark stays meaningful only for local.

## 4. Tests

- [x] 4.1 (no root) Forwarded arg builders: the rule contains `PREROUTING`(jump), `! -i lo`, `--dport 53`, the port, and NO `--mark`; Remove flushes/deletes only the dedicated fwd chain, never PREROUTING.
- [x] 4.2 (no root) Watchdog `Scope` selection via fake install/remove seams... (kept via the seam already present): assert ScopeForwarded installs the forwarded redirect, ScopeBoth both. (If the public seams don't allow per-scope observation, assert the arg-builder selection instead.)

## 5. Gated VM test

- [x] 5.1 A netns+veth forwarding topology (host = gateway, client in ns, ip_forward=1): a canned upstream on `127.0.0.2:53`; the resolver on a high port (`Upstream=127.0.0.2:53`, `Blocked={evil.example}`); `InstallForwarded(port)`. From the ns, `dig` a DNS-server IP in the routed range for `evil.example` → NXDOMAIN (sinkholed); for `good.example` → NOERROR (forwarded). `RemoveForwarded` cleans up. Build on the VM; paste the PASS.

## 6. Mutation verification

- [x] 6.1 (gated, VM) The forwarded install omits the PREROUTING jump (or the REDIRECT) → the ns `evil.example` query is not sinkholed (no NXDOMAIN) → the VM test FAILs. Revert.
- [x] 6.2 (no root) An arg-builder mutation the unit test catches: the forwarded rule drops `! -i lo` or the REDIRECT target → test 4.1 FAILs. Revert.

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (gated test SKIPS without root); proto-check clean; cross-compile clean.
- [x] 7.2 Run the gated VM test; paste the PASS + the mutation FAIL.
- [x] 7.3 decisions.md D-entry; sync the delta into `openspec/specs/dns-sinkhole/spec.md`; doccheck.
- [x] 7.4 Update the roadmap: NIPS-8 forwarded/gateway redirect DONE; note deferred (nft-native, TCP DNS, per-ingress scope, IPv6). Archive; commit; `git pull --rebase`; push.
