# Design — forwarded (gateway) DNS redirect

## Local vs forwarded

- **Local (D234):** nat `OUTPUT` REDIRECT of the host's own `:53`. Needs the mark loop-break, because the
  resolver's upstream forward is itself OUTPUT-generated `:53` and would be re-redirected into the resolver.
- **Forwarded (this):** nat `PREROUTING` REDIRECT of *forwarded* client `:53`. The resolver's upstream
  forward is locally-generated (OUTPUT), so it never traverses PREROUTING — no loop, **no mark exemption
  needed**. REDIRECT in PREROUTING maps the destination to the ingress interface's address, delivering the
  packet to the local resolver; conntrack reverses so the client sees a reply from the DNS server it asked.

```
client ─udp/53─▶ [nat PREROUTING: ! -i lo, dport 53 → REDIRECT :PORT] ─▶ resolver(:PORT)
                                                                            │ blocked → NXDOMAIN ─▶ client
resolver ─udp/53 (OUTPUT, not PREROUTING)─▶ real upstream ─▶ resolver ─▶ client
```

`! -i lo` keeps the gateway's own loopback `:53` out of the forwarded rule (the local rule, if also enabled,
handles the host itself).

## `internal/dnsredirect` — additive forwarded backend

New dedicated chain `OPENSHIELD_DNSREDIR_FWD` (separate from D234's `OPENSHIELD_DNSREDIR`). Pure arg
builders mirror the local ones but jump from PREROUTING and carry no mark:

- `iptablesForwardedInstallArgs(port)` → `-A OPENSHIELD_DNSREDIR_FWD ! -i lo -p udp --dport 53 -j REDIRECT
  --to-ports <port>` + the jump `-A PREROUTING -p udp --dport 53 -j OPENSHIELD_DNSREDIR_FWD`.
- `iptablesForwardedRemoveArgs()` → `-D PREROUTING …`, `-F`, `-X OPENSHIELD_DNSREDIR_FWD`.
- `InstallForwarded(port, log)` / `RemoveForwarded(log)` in `_linux.go` (iptables; nft-forwarded deferred);
  `_other.go` stubs. Remove-then-add idempotent, like D234. (nat REDIRECT works from a jumped user chain —
  proven by D234's OUTPUT chain; unlike TPROXY it needs no direct-PREROUTING placement.)

## Watchdog `Scope`

```go
type Scope int
const ( ScopeLocal Scope = iota; ScopeForwarded; ScopeBoth )
```

Add `Scope Scope` to `Watchdog` (default `ScopeLocal` — back-compatible). `doInstall` installs the local
redirect when the scope includes local and the forwarded redirect when it includes forwarded; `doRemove`
tears down both best-effort. So the D235 self-heal/bypass covers whichever redirects are active.

## Wiring

`applyDNSSink`: `OPENSHIELD_DNS_REDIRECT` now parses `local`/`1` → ScopeLocal, `forwarded` → ScopeForwarded,
`both` → ScopeBoth; set `Watchdog.Scope`. Mark is only meaningful for the local scope.

## Testing

- **(A) unit, no root** — the forwarded arg builders contain `PREROUTING`, `! -i lo`, `--dport 53`, the
  resolver port, and NO `--mark` (forwarded needs no exemption); Remove is the exact inverse (flush+delete
  the dedicated fwd chain, never PREROUTING itself). Watchdog `Scope` selects the right install/remove
  (via fakes: ScopeForwarded calls only the forwarded seam, ScopeBoth calls both).
- **(B) gated real-kernel VM test** — a netns+veth forwarding topology (the gateway is the host, the client
  is in the ns, `ip_forward=1`): a canned upstream on `127.0.0.2:53`; the resolver on a high port
  (`Upstream=127.0.0.2:53`, `Blocked={evil.example}`); `InstallForwarded(port)`. From the ns, `dig` a DNS
  server IP in the routed range for `evil.example` → **NXDOMAIN** (the forwarded query was transparently
  sinkholed); for `good.example` → **NOERROR** (forwarded to the real upstream). `RemoveForwarded` cleans up.
  Build on the VM; paste the PASS.

  **Mutation (VM):** the forwarded rule jumps nowhere / omits the REDIRECT → the ns query is not sinkholed
  (dig gets no NXDOMAIN) → the test FAILs.
