## 1. The portable flow handler (`internal/gateway/tproxy.go`)

- [x] 1.1 Types: `DecideFunc func(ctx, origDst, src net.Addr) (block bool, err error)`, `DialFunc func(origDst net.Addr) (net.Conn, error)`.
- [x] 1.2 `handleFlow(ctx, client net.Conn, origDst net.Addr, decide DecideFunc, dial DialFunc)`: call `decide`; on `block==true` → close client (drop); on error → treat as ALLOW (fail-open) and splice; else splice. Splice = dial origDst, `io.Copy` both directions in two goroutines, close both when either ends. A dial failure closes the client (upstream down — not a policy block).
- [x] 1.3 `TProxyServer` holding the gateway-backed `decide` (wraps `Gateway.Process` → BLOCK) and a `net.Dialer`-backed `dial`; `Serve(ctx, ln net.Listener)` accepts and dispatches each conn to `handleFlow` in its own goroutine (one stalled flow never blocks others).

## 2. The IP_TRANSPARENT listener

- [x] 2.1 `tproxy_linux.go` (`//go:build linux`): `ListenTransparent(addr string) (net.Listener, error)` — a `net.ListenConfig` with a `Control` that sets `SO_REUSEADDR` + `IP_TRANSPARENT` before bind, so the listener accepts TPROXY-redirected connections and each accepted conn's `LocalAddr()` is the ORIGINAL destination.
- [x] 2.2 `tproxy_other.go` (`//go:build !linux`): `ListenTransparent` returns an unsupported error (cross-compile).

## 3. Wiring

- [x] 3.1 `cmd/openshield-gateway/main.go`: when `OPENSHIELD_TPROXY_LISTEN` is set, `ListenTransparent` it and run `TProxyServer.Serve`; if the listen FAILS, log loudly and continue WITHOUT the inline plane (fail-to-wire, never fail-closed). Log the out-of-band iptables/nft TPROXY + routing requirement.

## 4. Tests

- [x] 4.1 `TestHandleFlowDrops` (no root): a fake origin echo server + a loopback client pair; `decide` returns block=true → the client conn is closed and the origin receives NO bytes.
- [x] 4.2 `TestHandleFlowSplices` (no root): `decide` block=false → bytes written by the client reach the origin and the origin's reply reaches the client (bidirectional).
- [x] 4.3 `TestHandleFlowFailOpen` (no root): `decide` returns an error → the flow is SPLICED (allowed), not dropped — egress fail-open.
- [x] 4.4 GATED real-kernel test `tproxy_kernel_test.go` (`requireTProxy(t)`: skip unless linux+root and `ListenTransparent` on a test addr succeeds): set up a network namespace + a veth pair + a mangle-PREROUTING TPROXY rule + the `ip rule`/`ip route local` so a flow FROM the netns to a test dst is redirected to the transparent listener; assert a flow to a DENIED dst is dropped and a flow to an ALLOWED dst reaches a real echo server. Run on the VM via a driver script (netns setup needs root); paste the result.

## 5. Mutation verification

- [x] 5.1 Mutation — `handleFlow` ignores `block` (always splices): `TestHandleFlowDrops` FAILs. Revert.
- [x] 5.2 Mutation — `handleFlow` treats a decide error as block (fail-CLOSED): `TestHandleFlowFailOpen` FAILs. Revert.
- [x] 5.3 Mutation (kernel, VM) — the listener omits `IP_TRANSPARENT`: `ListenTransparent`/the redirect fails to intercept → the gated test FAILs (or the bind/accept errors). Revert.

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green locally (the gated kernel test SKIPS without root); cross-compile clean.
- [x] 6.2 Run the gated TPROXY test on the VM (netns driver); paste the PASS into the D-entry.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: NIPS-1 TPROXY inline connector increment 1 DONE (the network plane drops a flow at L4; SNI/content-peek + bypass watchdog = increment 2). Archive; commit; `git pull --rebase`; push.
