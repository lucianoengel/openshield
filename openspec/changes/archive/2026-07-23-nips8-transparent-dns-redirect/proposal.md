# Transparent :53 redirect for the DNS sinkhole (NIPS-8 increment 2)

## Why
D231 shipped a real DNS sinkhole resolver (`internal/dnssink`): it forwards normal queries to an upstream
and answers a blocked domain with NXDOMAIN. But it only protects clients that are **explicitly configured**
to use it. An endpoint whose resolver is `8.8.8.8` (or a piece of malware that hard-codes its own resolver)
never touches the sinkhole. D231 named the fix as the next increment: *"the transparent :53 redirect
(DEPLOY-1) may now be built on top of this resolver."* A transparent redirect catches **unmodified**
clients' DNS with no reconfiguration — the difference between a resolver a careful admin can opt into and a
control that actually covers the fleet.

## What Changes
- **`internal/dnssink`** gains a `Mark` on the resolver: when set, its upstream forward socket carries a
  firewall mark (`SO_MARK`). When unset, behavior is unchanged.
- **New `internal/dnsredirect`**: installs a root-only nftables (or iptables) nat rule that transparently
  redirects locally-generated UDP `:53` traffic to the local resolver — **except** packets carrying the
  resolver's mark, so the resolver's own upstream queries escape the redirect. Idempotent install/remove in
  a dedicated table that never touches operator rules.
- **`cmd/openshield-gateway`** wires it behind `OPENSHIELD_DNS_REDIRECT=1` (on top of the existing
  `OPENSHIELD_DNS_SINK_LISTEN`): set the mark, install on startup, remove on shutdown, fail-to-wire loudly.

**The security-relevant core — the loop-break.** A naive "redirect all `:53` to the resolver" is an
infinite loop: the resolver's *own* forward to the real upstream is also `:53`, so it gets redirected back
into the resolver. The fix is a firewall-mark loop-breaker (the standard transparent-DNS-proxy pattern):
the resolver marks its upstream socket and the redirect rule exempts the mark. Both halves are
`CAP_NET_ADMIN`-gated (`SO_MARK` + nft nat), so this increment is proven on the rooted test VM.

## Impact
- Affected capability: `dns-sinkhole` (ADDED requirements — transparent redirect + the loop-break invariant).
- Affected code: `internal/dnssink` (additive `Mark` field + linux control), new `internal/dnsredirect`,
  `cmd/openshield-gateway` wiring.
- No proto change, no migration, no new dependency (`golang.org/x/sys/unix` already vendored; nft/iptables
  invoked as a subprocess like the TPROXY connector).
- **Deferred (stated):** the PREROUTING/gateway-forwarding case (redirect *other* hosts' `:53` for an inline
  gateway, vs this OUTPUT/local-host case); TCP DNS; a bypass watchdog that removes the redirect if the
  resolver dies (so name resolution is never wedged); DoT/DoH (`:853`/`:443` are not caught by a `:53`
  redirect and are the real evasion).
