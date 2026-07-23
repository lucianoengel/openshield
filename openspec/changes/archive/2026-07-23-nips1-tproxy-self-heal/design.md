# Design — self-healing transparent inline plane

## The loop

D238 gave us `RunTProxyWithRules` = install → serve → remove-on-stop. Self-heal wraps it in a supervision
loop that re-arms after an unexpected stop:

```
loop until ctx done:
  arm(ctx)          # create listener; RunTProxyWithRules (install → serve[blocks] → remove); close listener
  if ctx done: return
  backoff(ctx)      # wait, or return if ctx cancels during the wait
```

`arm` blocks while serving and returns when the server stops (or fast, if the listener can't be created).
Because a closed listener can't be reused, `arm` creates a **fresh** listener each iteration — so a re-arm
after an ephemeral-port listen also reinstalls rules for the new port (RunTProxyWithRules handles that).
Exit is only on ctx cancel; every other return path re-arms after the backoff.

## `gateway.SuperviseTProxy`

```go
func SuperviseTProxy(ctx context.Context, addr string, dports []int, mark, table int,
    retry time.Duration, newServer func() *TProxyServer, log *slog.Logger)
```

Delegates to a seam-injected core so the loop is unit-testable without root or real listeners:

```go
func superviseTProxy(ctx context.Context, arm func(context.Context) error,
    backoff func(context.Context) bool, log *slog.Logger) {
    for {
        if ctx.Err() != nil { return }
        if err := arm(ctx); err != nil && ctx.Err() == nil && log != nil {
            log.Error("...could not arm — will retry...", err)
        }
        if ctx.Err() != nil { return }
        if log != nil { log.Warn("...inline plane stopped — re-arming after backoff...") }
        if !backoff(ctx) { return }   // false = ctx cancelled during the wait
    }
}
```

The exported wrapper builds `arm` from `ListenTransparent` + `RunTProxyWithRules(newServer())`, and `backoff`
from an interruptible sleep (`sleepCtx`). `newServer` is a factory (a fresh `TProxyServer` per arm).

## Wiring

`applyTProxy`, self-install path: replace `go RunTProxyWithRules(ctx, ln, srv, …)` (which created the
listener once, up front) with `go SuperviseTProxy(ctx, addr, dports, mark, table, backoff, newServer, log)` —
the supervisor now owns listener creation. Drop the up-front `ListenTransparent` for that path (the
supervisor arms it; a bind failure is retried, not fatal). Backoff from `OPENSHIELD_TPROXY_RETRY` (default
5s). The operator-owns-rules path keeps the simple one-shot serve.

## Testing

- **(A) unit, no root** — `superviseTProxy` with fake `arm`/`backoff`:
  - `arm` returns immediately every time (simulating repeated death); `backoff` cancels the ctx after N
    iterations → `arm` was called N times and the loop exited on ctx (self-heal retries, then stops on
    cancel). **Mutation:** the loop `return`s after the first `arm` instead of looping → `arm` is called
    once → the "retried N times" assertion FAILs.
  - `backoff` returns false (ctx cancelled during the wait) → the loop exits promptly.
  - ctx already cancelled at entry → `arm` is never called.
- **(B) gated real-kernel VM test** — drive `superviseTProxy` with a real `arm` that creates a transparent
  listener, publishes it on a channel, then runs `RunTProxyWithRules`. The test: reads listener #1, confirms
  a forwarded flow is spliced (plane up); **closes listener #1** (server stops → rules removed → arm returns
  → supervisor re-arms); reads listener #2, confirms a forwarded flow is spliced **again** — proving the
  plane self-healed. Cancel ctx to stop.

  **Mutation (VM):** make the loop exit after the first `arm` return → listener #2 never appears → the test
  blocks on the channel and FAILs on timeout (no self-heal).
