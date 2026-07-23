# Self-installing TPROXY rules for the transparent inline plane (NIPS-1 increment 4a)

## Why
The transparent inline IPS (D225–227) provides the `IP_TRANSPARENT` listener and decides a TPROXY-redirected
flow at L4 — but it does NOT install the TPROXY plumbing. A deployer must hand-craft, out of band, the three
rules that actually get flows to the listener:

```
ip rule add fwmark <mark> lookup <table>
ip route add local 0.0.0.0/0 dev lo table <table>
iptables -t mangle -A PREROUTING -p tcp --dport <port> -j TPROXY --on-port <listen> --tproxy-mark <mark>
```

Getting these wrong (or leaving them behind on restart) is the main operability barrier to running the
transparent plane — and it is exactly the plumbing D234 taught OpenShield to own for the DNS redirect. This
brings the same discipline to TPROXY: OpenShield installs the rules (opt-in, idempotent, dedicated
chain/table, cleaned up on exit), so the inline plane is deployable, not a manual firewall exercise. It also
makes a future TPROXY bypass watchdog possible (OpenShield now owns the rules it can remove).

## What Changes
- **New `internal/gateway/tproxyrules.go`** (linux + portable stub): `InstallTProxyRules(listenPort int,
  dports []int, mark, table int)` installs the `ip rule` + divert `ip route` (in a dedicated routing table)
  + a mangle `PREROUTING` TPROXY rule per destination port (in a dedicated chain `OPENSHIELD_TPROXY`), all
  remove-then-add idempotent; `RemoveTProxyRules()` tears them down cleanly. Pure arg builders for unit
  testing.
- **`cmd/openshield-gateway`**: behind `OPENSHIELD_TPROXY_INSTALL_RULES=1` (on top of
  `OPENSHIELD_TPROXY_LISTEN`), parse the destination ports (`OPENSHIELD_TPROXY_DPORTS`, default `80,443`),
  install on startup, remove on shutdown; fail-to-wire (an install failure logs and the plane keeps running
  — the operator can still install rules out of band).

The blast radius (a broad divert route) is contained to a **dedicated routing table** used only by
mark-tagged packets via the `ip rule`, and torn down on exit; the iptables rule lives in a **dedicated
chain** so removal never touches operator firewall state.

## Impact
- Affected capability: `network-gateway` (ADDED requirement — self-installing TPROXY rules).
- Affected code: new `internal/gateway/tproxyrules.go` (+ stub), `cmd/openshield-gateway` wiring.
- No proto change, no migration, no new dependency (iptables/ip invoked as a subprocess, like D234).
- **Deferred (stated):** an nftables-native backend (this uses iptables-mangle + iproute2); a TPROXY bypass
  watchdog (now enabled by OpenShield owning the rules — the D235 analogue for L4); the locally-generated
  (OUTPUT) traffic case (TPROXY is PREROUTING/forwarded-traffic; a local-host divert needs an OUTPUT mark +
  reroute); IPv6; a configurable non-TCP set.
