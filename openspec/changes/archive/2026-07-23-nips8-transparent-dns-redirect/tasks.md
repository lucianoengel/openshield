## 1. Resolver upstream mark (`internal/dnssink`)

- [x] 1.1 Add `Mark int` to `Resolver`. In `forward`, when `Mark > 0` dial the upstream through a
  `net.Dialer{Timeout: r.timeout(), Control: markControl(r.Mark)}` instead of `net.DialTimeout`; when
  `Mark == 0` keep the exact existing `net.DialTimeout` path (D231 tests unchanged).
- [x] 1.2 `mark_linux.go` (build tag linux): `markControl(mark int) func(network,address string,c syscall.RawConn) error` runs `unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)` inside `c.Control`. `mark_other.go` (`!linux`): a control that is inert/unused (Mark only wired on linux), so the tree cross-compiles.

## 2. The redirect installer (`internal/dnsredirect`)

- [x] 2.1 Pure rule-argv builders (portable, no root): `nftRuleArgs(port, mark int) [][]string` (table/chain/rule create) and the iptables equivalent; a matching remove-argv. The rule encodes `udp dport 53`, `redirect to :<port>`, and the mark-exemption (`meta mark != <mark>` / `! --mark <mark>`), in a dedicated table/chain `openshield_dnsredirect`.
- [x] 2.2 `redirect_linux.go`: `Install(resolverPort, mark int) error` — Remove-then-add (delete a stale table first, TPROXY idempotency discipline), prefer nft, fall back to iptables, clear error if neither exists; `Remove() error` — delete the dedicated table/rule, ignore "not found" (idempotent). Loud logging.
- [x] 2.3 `redirect_other.go` (`!linux`): `Install`/`Remove` return `errUnsupported` ("transparent DNS redirect is linux-only").

## 3. Wiring (`cmd/openshield-gateway`)

- [x] 3.1 Behind `OPENSHIELD_DNS_REDIRECT=1` AND `OPENSHIELD_DNS_SINK_LISTEN` set: parse the resolver port, pick the mark (`OPENSHIELD_DNS_REDIRECT_MARK`, default `0x1d5`), set `Resolver.Mark`, `dnsredirect.Install(port, mark)` on startup, `Remove()` on shutdown. An nft/install failure logs loudly and the gateway keeps running (fail-to-wire, never fail-to-boot); the resolver still serves explicitly-configured clients.

## 4. Tests

- [x] 4.1 (no root) `dnsredirect` rule-argv: the generated nft/iptables argv contains `dport 53`, the resolver port, and the mark-exemption; the remove argv is the inverse; the `!linux` stub returns the unsupported error.
- [x] 4.2 (no root) `dnssink`: `Mark == 0` takes the plain-dial path (a forward test against a stub upstream still passes, byte-for-byte behavior unchanged); `Mark > 0` builds a dialer with a non-nil control (assert the control path is selected; the actual `SetsockoptInt` is exercised only under the gated test).

## 5. Gated VM test

- [x] 5.1 A gated real-kernel test (`requireRoot` + linux + nft/iptables present, else skip), self-contained on loopback: a canned UDP upstream DNS responder on `127.0.0.2:53` (fixed A record); the resolver on a high port with `Upstream=127.0.0.2:53`, a `Mark`, `Blocked={evil.example}`; `Install(resolverPort, mark)`; a client raw-UDP query to `127.0.0.2:53` for `evil.example` → NXDOMAIN (transparently sinkholed); for `good.example` → the resolver forwards it (marked, escapes the redirect) to the real `127.0.0.2:53` upstream and relays the A answer; `Remove()` cleans up. Build on the VM (`go test -c` + scp + `sudo`); paste the PASS.

## 6. Mutation verification

- [x] 6.1 (gated, VM) `Install` omits the mark-exemption (redirect ALL `dport 53`) → the resolver's own upstream forward loops back to itself → the `good.example` query never reaches the upstream → times out with no answer → the gated test FAILs. Revert. (This is the load-bearing loop-break guard.)
- [x] 6.2 (no root) A rule-argv mutation the unit test catches: the builder drops the mark-exemption token → test 4.1 FAILs (the argv no longer contains the exemption). Revert.

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (the gated test SKIPS without root); `proto-check` clean (no proto change); cross-compile clean (`!linux` stubs).
- [x] 7.2 Run the gated VM test; paste the PASS + the mutation FAIL.
- [x] 7.3 decisions.md D-entry; sync the delta into `openspec/specs/dns-sinkhole/spec.md`; doccheck.
- [x] 7.4 Update the roadmap: NIPS-8 increment 2 (transparent redirect) DONE; note deferred (PREROUTING/gateway-forward case, TCP DNS, bypass watchdog, DoT/DoH). Archive; commit; `git pull --rebase`; push.
