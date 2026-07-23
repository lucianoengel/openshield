# Bypass watchdog for the transparent DNS redirect (NIPS-8 increment 3)

## Why
D234 shipped the transparent `:53` redirect: the host's DNS is transparently routed to the local sinkhole
resolver. That introduces a real availability hole — **if the resolver wedges or crashes while the redirect
is installed, every DNS query on the host is redirected into a dead socket and name resolution fails
completely.** D234 explicitly deferred the fix and flagged it: *"a bypass watchdog that removes the redirect
if the resolver dies (so name resolution is never wedged)."* This is the D73/D17 fail-open discipline
applied to the redirect itself: an availability failure of the control must get out of the way, never take
the fleet's name resolution down with it.

## What Changes
- **New `dnsredirect.Watchdog`**: owns the redirect lifecycle around a liveness probe of the resolver.
  It installs the redirect, probes the resolver on an interval, and after a threshold of consecutive probe
  failures **removes the redirect (bypass)** so the host falls back to direct DNS; when the resolver
  recovers it **re-installs** the redirect. On shutdown it removes the redirect.
- **`cmd/openshield-gateway`**: when the transparent redirect is enabled, run it through the Watchdog
  instead of a bare `Install`, so a resolver failure self-heals to direct resolution.

The state machine (install / probe / bypass-on-failure / restore-on-recovery / remove-on-exit) is built with
injectable install/remove/probe hooks so it is fully unit-testable without root, and proven end-to-end on
the rooted VM: with the resolver up a blocked domain is sinkholed; when the resolver is killed the watchdog
removes the redirect and the same query resolves directly (the sinkhole bypassed) instead of hanging.

## Impact
- Affected capability: `dns-sinkhole` (ADDED requirement — the redirect bypass watchdog / self-healing
  availability invariant).
- Affected code: new `dnsredirect.Watchdog` (+ a default DNS liveness probe), `cmd/openshield-gateway`
  wiring.
- No proto change, no migration, no new dependency.
- **Deferred (stated):** a shared watchdog for the TPROXY redirect (NIPS-1 increment 4 — same idea, different
  mechanism); flap damping beyond a consecutive-failure threshold (exponential backoff / hold-down); an
  operator alert when a bypass fires (the notify seam); a liveness probe that is independent of the upstream
  (a reserved always-answered sentinel name) so an upstream outage does not trigger a bypass.
