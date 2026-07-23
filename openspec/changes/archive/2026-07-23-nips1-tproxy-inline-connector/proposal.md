## Why

The gateway inspects and blocks only traffic sent to it as an **explicit** HTTP proxy (or CONNECT). A
host on the network that talks directly to a destination is never seen — so OpenShield cannot drop an
arbitrary TCP flow to a known-bad endpoint. That is the gap between "an HTTP proxy" and "an inline
network IPS." NIPS-2 shipped the detection engine (IOC metadata D-earlier + content signatures D221);
NIPS-1 is the **transparent data-plane** that puts it in-line: a TPROXY listener that intercepts
redirected flows, recovers the original destination, runs the pipeline, and **drops** a blocked flow at
L4 — with the deliberate egress fail-open preserved (fail-to-wire, never fail-closed-the-network,
ADR-8/D73/D17). The rooted VM (`CAP_NET_ADMIN` + iptables) makes it buildable and provable.

## What Changes

- **New transparent TPROXY listener** (`internal/gateway`, linux + portable stub): a TCP listener with
  `IP_TRANSPARENT`, so an nftables/iptables TPROXY rule can redirect flows to it and the accepted
  connection's `LocalAddr()` is the **original destination** (TPROXY preserves it — no `SO_ORIGINAL_DST`
  needed).
- **A flow handler** that, per accepted connection, builds a metadata flow (src, original dst/port),
  runs `Gateway.Process`, and either **drops** the flow (closes the client — a real inline block at L4)
  or **splices** it bidirectionally to the original destination. It reuses the same pipeline the explicit
  proxy runs, so an IOC/dst-IP threat match blocks the flow.
- **Egress fail-open is load-bearing:** a pipeline error, or any handler failure, **splices the flow
  through** (allows egress) rather than dropping it — inline prevention must degrade to a passive wire,
  never a network outage. If the listener cannot be created (no `CAP_NET_ADMIN`), the connector
  **fails to wire** (logs and stays off); the rest of the gateway runs unaffected.
- **Wiring:** opt-in behind `OPENSHIELD_TPROXY_LISTEN`; off by default (an inline data-plane is an
  explicit deploy choice, ADR-8).

## Capabilities

### New Capabilities
<!-- none — extends the existing network-gateway capability with the transparent data-plane. -->

### Modified Capabilities
- `network-gateway`: add a **transparent (TPROXY) inline mode** that intercepts a redirected TCP flow,
  decides it through the pipeline, and drops a blocked flow at L4 while splicing an allowed one — with
  egress fail-open preserved (a pipeline failure forwards the flow, never blackholes it).

## Impact

- **Code:** new `internal/gateway/tproxy_linux.go` (the `IP_TRANSPARENT` listener) + `tproxy.go` (the
  portable flow handler: decide → drop/splice → fail-open) + `tproxy_other.go` stub; wiring in
  `cmd/openshield-gateway`. No proto, no migration, no new dependency (`golang.org/x/sys/unix`).
- **Testing:** the handler logic (drop / splice / fail-open) is unit-tested over loopback with an
  injected decision and a fake origin — no root. A **gated** real-kernel test sets up TPROXY via network
  namespaces on the VM and proves a real flow to a denied destination is dropped while an allowed one
  connects; skipped without root/`CAP_NET_ADMIN`.
- **Deferred (increment 2, stated honestly):** SNI/ClientHello peek + content-signature inspection over
  the flow bytes (increment 1 decides on L4 metadata — dst IP/port — via the IOC feed); a bypass
  watchdog that auto-disables the redirect if the handler wedges; UDP; nftables-native config; and the
  DNS transparent redirect (NIPS-8, needs the resolver first).
