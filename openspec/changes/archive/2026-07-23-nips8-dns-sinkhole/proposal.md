## Why

OpenShield sees DNS today only as a **tap** — the DNS connector parses queries into events for detection,
but a passive tap cannot stop anything: a device asked for a known-malware C2 domain, the resolver
answered, and the connection proceeded. To make DNS **preventive** it must become a real inline
**resolver** that can refuse a malicious name. This increment builds that: a UDP DNS resolver that
forwards normal queries to an upstream and **sinkholes** a policy/IOC-blocked domain (answers NXDOMAIN),
so a query for a known-bad domain resolves to nothing and the connection never starts (RPZ-style). It
**fails open** (a resolver problem forwards the query, never blackholes the fleet's name resolution) —
the D73/D17 discipline the roadmap requires before DNS prevention ships.

## What Changes

- **A real DNS resolver** (`internal/dnssink`): reads a UDP query, parses the name (reusing the hardened
  `dns.ParseQuery`), and either **sinkholes** it (a blocked domain → an NXDOMAIN response, built from the
  query so the client sees a well-formed "no such domain") or **forwards** it to a configured upstream
  and relays the response. Subdomains of a blocked domain are also sinkholed.
- **Fail-open is load-bearing:** a query the resolver cannot parse or classify is **forwarded**, not
  dropped — a resolver that blackholes on a bad input or a classification gap would take out the fleet's
  name resolution. The block set only sinkholes what it is sure is bad.
- **Backed by the IOC feed:** the blocked-domain check is the same `nips.Feed` domain match the inline
  IPS uses (hot-reloadable), so a domain added to threat intel is sinkholed with no restart.
- **Wiring:** opt-in behind `OPENSHIELD_DNS_SINK_LISTEN` (the resolver's UDP bind — `:53` in production,
  which needs privilege; any port for a dev/test bind) + `OPENSHIELD_DNS_UPSTREAM` (the real resolver to
  forward to). Off by default.

## Capabilities

### New Capabilities
- `dns-sinkhole`: a preventive DNS resolver that forwards normal queries upstream and sinkholes a
  blocked domain (NXDOMAIN), failing open so a resolver problem never blackholes name resolution.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** new `internal/dnssink` (the resolver + NXDOMAIN builder), reusing `dns.ParseQuery` and
  `nips.Feed`; wiring in `cmd/openshield-gateway` (it already loads the IOC feed). No proto, no migration,
  no new dependency.
- **Testing:** the resolver is testable locally on a high UDP port (only binding `:53` needs privilege):
  a query for a blocked domain → NXDOMAIN (sinkholed, upstream never queried); a normal query → forwarded
  to a stub upstream and the response relayed; an unparseable query → forwarded (fail-open). A VM run
  binds a real port under privilege.
- **Deferred (later increments):** a local cache + upstream failover; the transparent `:53` redirect
  (DEPLOY-1) — must not ship until this resolver exists and is proven; a sinkhole-to-walled-garden IP
  option (increment 1 returns NXDOMAIN); TCP DNS and DoT/DoH; a bypass watchdog for a wedged resolver.
