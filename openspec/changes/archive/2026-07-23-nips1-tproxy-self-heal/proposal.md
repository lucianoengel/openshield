# Self-heal the transparent inline plane (NIPS-1 increment 4c)

## Why
D238 made the TPROXY rules fail-open: when the inline server stops, the rules are removed so traffic falls
back to direct routing instead of black-holing. That is the safe outcome, but it is not the *complete*
outcome — after a transient listener/accept failure the inline plane stays **down** for the rest of the
process's life, silently losing all inline network prevention (a blocked-domain flow that would have been
dropped now passes). The operator's only recovery is a full restart. A supervised plane should recover on
its own: re-arm the listener, reinstall the rules, resume enforcing.

## What Changes
- **New `gateway.SuperviseTProxy`**: a supervision loop that (re)creates the transparent listener,
  runs the rule-bound server (D238's `RunTProxyWithRules`), and — when it stops for any reason other than a
  context cancel — waits a backoff and **re-arms**, until the context is cancelled. A listener that cannot
  be created is retried the same way (fail-to-wire without giving up).
- **`cmd/openshield-gateway`** uses it on the self-install path, so the listener is created and owned by the
  supervisor (not once up front); the operator-owns-rules path is unchanged.

The supervision loop (arm → serve → backoff → re-arm, exit on ctx) is factored behind seams so its retry and
ctx-exit behavior is unit-testable without root, and proven on the VM: with the plane serving a flow is
enforced; when the listener is killed the supervisor re-arms and a subsequent flow is enforced again.

## Impact
- Affected capability: `network-gateway` (ADDED requirement — the inline plane self-heals after an
  unexpected stop).
- Affected code: new `gateway.SuperviseTProxy` (+ an unexported testable core), `cmd/openshield-gateway`
  wiring.
- No proto change, no migration, no new dependency.
- **Deferred (stated):** self-heal for the operator-owns-rules path (this covers the self-install path,
  where D238's rule lifecycle lives); a crash-loop circuit breaker / exponential backoff (this is a fixed
  backoff); a synthetic liveness probe for a HUNG (not stopped) listener; the nftables-native backend.
