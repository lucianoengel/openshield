# Bind the TPROXY rule lifecycle to the inline server (NIPS-1 increment 4b)

## Why
D237 made OpenShield own the TPROXY redirect rules, removing them on process shutdown (`ctx.Done()`). But
the rule teardown is bound to the **process** lifecycle, not the **server** lifecycle: if the transparent
inline server (the `IP_TRANSPARENT` listener / `Serve` loop) stops mid-run — a listener error, an accept
failure — while the process keeps running, the redirect rules stay installed and point at a **dead
listener**. Every forwarded flow on the watched ports is then redirected into a closed socket
(connection-refused / black-holed), so the host loses egress on :80/:443 until the process exits. This is
the D73/D17 fail-open discipline applied to the rules: a redirect must never outlive the thing it redirects
into.

## What Changes
- **New `gateway.RunTProxyWithRules`**: installs the TPROXY rules, runs the inline server, and removes the
  rules the instant `Serve` returns — for **any** reason (unexpected stop *or* ctx cancel). The rules'
  lifetime is now exactly the server's lifetime.
- **`cmd/openshield-gateway`** uses it on the self-install path (`OPENSHIELD_TPROXY_INSTALL_RULES=1`),
  replacing the separate Serve-goroutine + remove-on-`ctx.Done()` pair. The operator-owns-rules path
  (install-rules off) is unchanged — OpenShield only manages the lifecycle of rules it installed.

The rule-lifecycle logic is factored behind install/remove/serve seams so it is unit-testable without root,
and proven on the VM: with the server up a forwarded flow is redirected; when the listener is closed (the
server stops) while the process keeps running, the rules are gone and the flow is no longer redirected.

## Impact
- Affected capability: `network-gateway` (ADDED requirement — the rule lifecycle is bound to the inline
  server).
- Affected code: new `gateway.RunTProxyWithRules` (+ an unexported testable core), `cmd/openshield-gateway`
  wiring.
- No proto change, no migration, no new dependency.
- **Deferred (stated):** automatic **self-heal** (re-arm the listener + reinstall after an unexpected stop,
  with backoff) — this increment removes the stale rules (fail-open) but does not yet restart the plane; a
  synthetic liveness probe for a *hung* (not stopped) listener; the nftables-native backend.
