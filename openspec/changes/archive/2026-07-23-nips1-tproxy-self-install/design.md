# Design — self-installing TPROXY rules

## The three rules, and why each

To get a forwarded TCP flow into the `IP_TRANSPARENT` listener, TPROXY needs:

1. **`iptables -t mangle -A <chain> -p tcp --dport <port> -j TPROXY --on-port <listen> --tproxy-mark <mark>`**
   — the mangle/PREROUTING rule that catches a forwarded flow, marks it, and hands it to the listener
   socket without changing its destination (so `LocalAddr` still reveals the original dst).
2. **`ip rule add fwmark <mark> lookup <table>`** — route marked packets via a dedicated routing table.
3. **`ip route add local 0.0.0.0/0 dev lo table <table>`** — that table treats every destination as local,
   so the marked packet is delivered up to the local listener instead of being forwarded on.

Rules 2–3 are the part with blast radius (a broad "everything is local" route). Containment: the route
lives in a **dedicated routing table** reached ONLY by mark-tagged packets through rule 2 (so unmarked host
traffic is unaffected), and rule 1 is deleted by **exact spec** (`-D`) on teardown so operator PREROUTING
rules are never touched. Everything is remove-then-add idempotent and removed on exit — the D234/TPROXY-test
discipline.

**Two correctness cores, both found on the VM (the "verifies against its own assumptions" failure mode
punished by real hardware):**
- **Direct PREROUTING, not a jumped sub-chain.** The first VM run put the TPROXY rule in a dedicated chain
  jumped from PREROUTING; the flow timed out. `xt_TPROXY` diverts reliably only when the rule runs in the
  PREROUTING hook context directly, so the rule goes straight into PREROUTING (`-A PREROUTING`), deleted by
  exact `-D` on teardown (still scoped — it never flushes PREROUTING).
- **`! -i lo` — never TPROXY loopback.** The second VM run still timed out: without excluding loopback, the
  transparent server's OWN upstream dial (when the destination is local) re-enters PREROUTING, matches the
  dport rule, and is diverted right back into the listener — the flow wedges. A gateway must never TPROXY
  its own loopback traffic; `! -i lo` fixes it and is correct in production (a real bug, not a test artifact).

## `internal/gateway/tproxyrules.go`

Pure builders (portable, unit-testable without root):

```go
func tproxyInstallArgs(listenPort int, dports []int, mark, table int) (ip [][]string, ipt [][]string)
func tproxyRemoveArgs(listenPort int, dports []int, mark, table int) (ip [][]string, ipt [][]string)
```

- `ip` sequence: `rule add fwmark <mark> lookup <table>`, `route add local 0.0.0.0/0 dev lo table <table>`.
- `ipt` sequence: per dport `-t mangle -A PREROUTING ! -i lo -p tcp --dport <port> -j TPROXY --on-port
  <listen> --tproxy-mark <mark>`.
- Remove: the exact `-D PREROUTING …` per dport (idempotent), then `ip rule del fwmark <mark> lookup <table>`
  and `ip route flush table <table>` — never `-F PREROUTING` or the main table.

Linux `InstallTProxyRules`/`RemoveTProxyRules` exec these (best-effort teardown/scaffold, fatal rule-adds),
prefer `iptables` + `ip`. A `!linux` stub returns a clear "linux-only" error.

## Wiring

`applyTProxy`: when `OPENSHIELD_TPROXY_INSTALL_RULES=1`, after the listener arms, parse the listener port +
`OPENSHIELD_TPROXY_DPORTS` (default `80,443`), pick a mark (`OPENSHIELD_TPROXY_MARK`, default `1`) and a
dedicated table (`OPENSHIELD_TPROXY_TABLE`, default `100`), `InstallTProxyRules(...)`, and `RemoveTProxyRules`
on `ctx.Done()`. An install failure logs loudly and the plane keeps running (the operator can still install
rules out of band) — never fail-closed.

## Testing

- **(A) unit, no root** — the arg builders: the `ip` sequence contains the fwmark rule + the divert route in
  the dedicated table; the iptables sequence contains a per-dport TPROXY rule (`--on-port`, `--tproxy-mark`)
  in the dedicated chain + the PREROUTING jump; Remove is the inverse and never touches PREROUTING's other
  rules or the main routing table; the `!linux` stub errors clearly.
- **(B) gated real-kernel VM test** — reuse the existing netns+veth topology, but install the TPROXY
  plumbing with `InstallTProxyRules` instead of the manual rule lines; a flow from the namespace to a blocked
  dst is DROPPED and to an allowed dst is SPLICED — proving the self-installed rules actually deliver flows
  to the transparent listener. `RemoveTProxyRules` cleans up.

  **Mutation:** drop the divert `ip route`/`ip rule` (rules 2–3) from Install → a marked packet is not
  delivered locally → the flow never reaches the listener → the allowed-flow splice times out → the test
  FAILs. Proves the routing half is load-bearing, not just the iptables rule.

Gated like the existing `tproxy_kernel_test` (skip without root + `ip`/`iptables`); run on the VM via
`go test -c` + scp + `sudo`.
