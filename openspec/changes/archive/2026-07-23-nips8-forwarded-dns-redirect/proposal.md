# Forwarded (gateway) DNS redirect for the sinkhole (NIPS-8 increment 4)

## Why
D234's transparent `:53` redirect catches only **locally-originated** DNS (an nat OUTPUT rule), so it
protects the gateway host's own queries. But OpenShield's inline network deployment is a **gateway** —
client traffic is *forwarded* through it. In that mode client DNS never traverses the OUTPUT chain, so it
bypasses the sinkhole entirely: the transparent redirect covers the gateway itself but not a single client
behind it. D234 named this deferral: *"the PREROUTING/gateway-forwarding case (redirect OTHER hosts' :53 for
a real inline gateway, vs this OUTPUT/local-host case)."* This adds it, so the sinkhole works where it
matters most — as a network gateway for a fleet of clients.

## What Changes
- **`internal/dnsredirect`** gains a **forwarded** redirect: an nat `PREROUTING` REDIRECT of forwarded UDP
  `:53` into the local resolver, in its own dedicated chain (`OPENSHIELD_DNSREDIR_FWD`). `InstallForwarded`
  / `RemoveForwarded`, additive — D234's local `Install`/`Remove` are untouched.
- **`dnsredirect.Watchdog`** gains a `Scope` (local / forwarded / both) so the self-heal bypass (D235)
  covers the forwarded redirect too.
- **`cmd/openshield-gateway`** accepts `OPENSHIELD_DNS_REDIRECT = local | forwarded | both` (`1` = local,
  back-compatible).

**A simplification the forwarded case allows:** the OUTPUT redirect needed a firewall-mark loop-break
(D234) because the resolver's own upstream forward is also `:53` and would loop. A PREROUTING redirect does
NOT — the resolver's upstream query is locally-generated (OUTPUT), so it never traverses PREROUTING and is
not caught. The forwarded rule therefore needs no mark exemption (it excludes loopback with `! -i lo`).

## Impact
- Affected capability: `dns-sinkhole` (ADDED requirement — the forwarded/gateway redirect).
- Affected code: `internal/dnsredirect` (additive forwarded install/remove + Watchdog `Scope`),
  `cmd/openshield-gateway` wiring.
- No proto change, no migration, no new dependency (iptables as a subprocess, like D234).
- **Deferred (stated):** the nftables-native forwarded backend (this is iptables); TCP DNS; per-ingress-
  interface scoping (this redirects all non-loopback ingress `:53`); IPv6.
