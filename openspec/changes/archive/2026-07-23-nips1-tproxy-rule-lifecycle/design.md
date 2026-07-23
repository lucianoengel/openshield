# Design — TPROXY rule lifecycle bound to the server

## The invariant

The redirect rules must exist **iff** the inline server is running. D237 removed them on `ctx.Done()`, which
covers a clean shutdown but not an early `Serve` return (listener/accept error). The fix binds removal to
`Serve` returning:

```
install rules → Serve (blocks) → remove rules   [whatever made Serve return]
```

So the rules are torn down the instant the server stops, and forwarded flows fall back to direct routing
(fail-open) rather than being redirected into a dead socket.

## `gateway.RunTProxyWithRules`

```go
func RunTProxyWithRules(ctx context.Context, ln net.Listener, srv *TProxyServer,
    port int, dports []int, mark, table int, log *slog.Logger)
```

Blocks until `Serve` returns; the caller runs it in a goroutine. It delegates to an unexported core with
seams so the lifecycle is unit-testable without root:

```go
func runTProxyWithRules(ctx context.Context, serve func(context.Context) error,
    install func() error, remove func(), log *slog.Logger) {
    installed := install() == nil
    if !installed { log.Error("...rules not installed; serving without the transparent redirect...") }
    serveErr := serve(ctx)
    if installed { remove() }        // rules never outlive the server
    if serveErr != nil && ctx.Err() == nil {
        log.Error("...inline server stopped unexpectedly — redirect rules removed, traffic falls back to direct...")
    }
}
```

- `remove()` is called only if `install()` succeeded (never delete rules we did not add).
- `remove()` runs on **every** `Serve` return, not only ctx cancel — that is the whole fix.
- `RemoveTProxyRules` is idempotent, so a later process-shutdown teardown is harmless.

## Wiring

`applyTProxy`, self-install path: replace the `go srv.Serve(...)` + `go func(){ <-ctx.Done(); Remove() }()`
pair with `go gateway.RunTProxyWithRules(ctx, ln, srv, port, dports, mark, table, log)`. The
operator-owns-rules path (install-rules unset) keeps the plain `go srv.Serve(...)` — OpenShield manages only
the lifecycle of rules it installed.

## Testing

- **(A) unit, no root** — `runTProxyWithRules` with fake seams:
  - `serve` returns (an error, ctx still live) → `remove` is called exactly once; the "unexpected stop" is
    logged. **Mutation:** bind remove to `ctx.Done()` instead of the serve-return → with a serve that
    returns before ctx cancel, `remove` is never called → the "remove called on server stop" assertion FAILs.
  - `install` fails → `serve` still runs, `remove` is NOT called (never delete rules we did not add).
  - ctx cancel makes `serve` return → `remove` called (the D237 path still holds).
- **(B) gated real-kernel VM test** — reuse the netns topology; run `RunTProxyWithRules` in a goroutine over
  a real transparent listener + self-installed rules; assert a forwarded flow is spliced (rules active +
  redirecting). Then **close the listener** (making `Serve` return) with the ctx still live, and assert the
  TPROXY rule is GONE (`iptables -t mangle -C … ` returns non-zero) — the rules were removed the moment the
  server stopped, not left pointing at a dead socket.

  **Mutation (VM):** remove rules only on ctx cancel (not on serve-return) → after the listener closes the
  rule is still present → the "rule is gone" assertion FAILs.
