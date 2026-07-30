# Design

## One policy, not four call sites

Nine `nats.Connect` call sites, four of them long-lived processes. Fixing each would guarantee the fifth
one added later is wrong, so the policy is a single exported function in `internal/transport/nats` and the
callers append it.

The engine and gateway are the instructive case. Their `natsOptions(log)` looked like it existed to hold
exactly this, and returned `nil` when TLS was unconfigured:

```go
if cfg == nil {
    return nil            // ← the common path: no options at all
}
return []nats.Option{nats.Secure(cfg.ClientConfig())}
```

So the resilience of the connection depended on whether mTLS happened to be turned on. Nothing in the name
or the shape of that function suggests it.

## Why the callback rather than a logger

Callers log three different ways — `slog` in the engine, gateway and control plane; `fmt.Fprintf(os.Stderr)`
in the agent. A package this low picking one would force the others to adapt or to wrap. `func(string)`
lets each keep its own format, and a nil callback is accepted (reconnect forever, quietly) while being
explicitly documented as giving up the D31 half.

## Why there is no ClosedHandler

The obvious addition is a handler logging "connection closed permanently — this process will never publish
again" at maximum severity. It is wrong twice.

nats.go invokes `ClosedHandler` on an explicit `Close()` as well as on giving up, so that line would appear
on **every clean shutdown**. A maximum-severity warning present in the log of every correctly-stopped
machine is the one an operator learns to scroll past, and it would actively mislead during incident review.

And the condition it warns about can no longer occur: with `MaxReconnects(-1)` the client never gives up on
its own, so a permanent close is only ever a deliberate one. The handler would add no signal at the cost of
the log's credibility.

## The mutation caught a test that could not fail

The first version of the scenario used a 135-second outage, reasoning that 60 attempts × 2s = 120s. Setting
`MaxReconnects(60)` back left it **passing** — because the jitter this change also adds makes the real
budget 120–180s, so 135s never exhausted it. The scenario was quietly re-proving what the drain scenario
already covered.

The window is now 200s, past the jittered worst case. Verified in both directions: the mutant fails on the
spool never draining (383s), the fixed version passes with 80 records recovered (209s).

Worth recording as a pattern rather than a one-off: **the fix widened the very budget the test was sized
against.** Any test whose threshold is derived from the code under test has to be re-derived after the code
changes, and the mutation is the only thing that catches it.
