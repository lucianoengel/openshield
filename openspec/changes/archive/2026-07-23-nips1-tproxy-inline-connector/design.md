## Context

`Gateway.Process(req *Request) (*Decision, error)` runs the network pipeline (classify + IOC threat +
content signatures + policy) and returns a decision; the explicit proxy already uses it and reads a
`Disposition` from the flow `Table`. For a raw L4 flow there is no HTTP body, but the IOC threat stage
matches on destination IP/CIDR, so a metadata-only `Request{SrcIP, DstIP, DstPort, Direction: EGRESS}`
yields a real block decision for a flow to a known-bad endpoint. The missing piece is the transparent
data-plane that presents such flows to the pipeline and acts on the verdict at L4.

## Goals / Non-Goals

**Goals:**
- Transparently intercept a redirected TCP flow, recover its original destination, decide it through the
  pipeline, and DROP a blocked flow / SPLICE an allowed one at L4.
- Preserve egress fail-open: a pipeline or handler failure forwards the flow; a listener that can't be
  created fails to wire (never fails the network closed).
- Opt-in; off by default.

**Non-Goals (increment 2):** SNI/ClientHello peek + content-signature bytes inspection (increment 1 is
L4 metadata / dst-IP); a bypass watchdog auto-disabling a wedged redirect; UDP; nftables-native rule
management; the DNS transparent redirect (NIPS-8).

## Decisions

1. **TPROXY, not L2 bridge or REDIRECT (ADR-8).** A listener socket with `IP_TRANSPARENT` accepts
   TPROXY-redirected connections, and the accepted conn's `LocalAddr()` is the **original destination**
   — TPROXY preserves it, so no `getsockopt(SO_ORIGINAL_DST)`. This is the ADR-8-fixed approach; L2
   bridging is rejected.

2. **The handler is portable and injectable; only the socket is linux.** `tproxy.go` holds
   `handleFlow(client net.Conn, origDst net.Addr, decide DecideFunc, dial DialFunc)`:
   - `decide(origDst, src) (block bool, err error)` — production wraps `Gateway.Process`.
   - On `block==true`: close the client (the flow is dropped — a real inline refusal).
   - Else: `dial(origDst)` the real destination and splice bidirectionally (`io.Copy` both ways, close
     when either side ends).
   - **Fail-open:** if `decide` returns an error, treat it as ALLOW and splice — a detection failure must
     not break egress (D73/D17). A `dial` failure is a normal upstream-down outcome (the flow just
     ends), not a policy block.
   This makes the drop/splice/fail-open logic unit-testable over loopback with a fake origin, no root.

3. **`IP_TRANSPARENT` listener (`tproxy_linux.go`).** Create the socket, `setsockopt(SOL_IP,
   IP_TRANSPARENT, 1)` and `SO_REUSEADDR` before bind, then listen. A `tproxy_other.go` stub returns an
   unsupported error so the tree cross-compiles.

4. **Fail-to-wire, never fail-closed.** `cmd/openshield-gateway` starts the TPROXY server only when
   `OPENSHIELD_TPROXY_LISTEN` is set; if the listener cannot be created (missing `CAP_NET_ADMIN`), it
   logs loudly and the gateway continues WITHOUT the inline plane — the network is never taken down
   because inline could not arm. The operator installs the iptables/nft TPROXY + routing rules out of
   band (documented); the connector owns only the socket and the flow handling.

## Risks / Trade-offs

- **TPROXY intercepts forwarded traffic, not locally-originated** (kernel constraint). Real use is on a
  gateway/router the fleet's egress passes through; the VM test therefore routes traffic through a
  network namespace so it hits the PREROUTING TPROXY rule — the faithful topology.
- **L4-only decision in increment 1.** A flow to a known-bad IP is blocked; a flow to a shared CDN IP
  carrying a bad SNI is not (that needs the ClientHello peek — increment 2). Stated honestly; the IOC
  dst-IP block is real and useful now.
- **A wedged handler could stall flows.** Increment 1 relies on the fail-open path and per-splice
  independence; an auto-disable bypass watchdog (ADR-8) is increment 2. Each flow is handled in its own
  goroutine, so one stalled flow does not block others.
- **The gated test needs root + `CAP_NET_ADMIN` + netns**; skipped in the default suite and current CI,
  proven on the VM. A privileged CI job is a follow-up.
