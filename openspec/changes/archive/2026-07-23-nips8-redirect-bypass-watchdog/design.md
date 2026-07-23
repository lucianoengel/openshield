# Design — DNS redirect bypass watchdog

## The availability invariant

A transparent redirect is a single point of failure for name resolution: every `:53` query on the host is
sent to the local resolver. If the resolver is healthy this is exactly what we want; if it wedges, the host
goes dark for DNS. The watchdog makes the redirect **self-limiting**: it is installed only while the
resolver demonstrably answers, and it is torn down the moment the resolver stops — falling back to the
client's own direct DNS (fail-open, D73/D17). A bypass is loud (it is a degraded security posture — the
sinkhole is temporarily not covering unconfigured clients) but it is strictly better than a wedged fleet.

## `dnsredirect.Watchdog`

```go
type Watchdog struct {
    Port, Mark int
    Interval   time.Duration // probe cadence (default 5s)
    Failures   int           // consecutive failures before bypass (default 3)
    Probe      func() bool   // resolver liveness; nil → the default DNS probe against 127.0.0.1:Port
    Log        *slog.Logger

    // install/remove are indirection points for tests; nil → dnsredirect.Install/Remove.
    install func() error
    remove  func()
}

func (w *Watchdog) Run(ctx context.Context) // install, probe-loop, bypass/restore, remove on ctx.Done
```

State: `installed bool`, `consecutiveFailures int`.

- **Start**: `install()`; `installed = true` (if install fails, log and start bypassed — the redirect is
  optional, the resolver still serves configured clients).
- **Each tick**:
  - `Probe()` true → reset `consecutiveFailures = 0`; if currently bypassed, `install()` and log
    "resolver recovered — redirect restored".
  - `Probe()` false → `consecutiveFailures++`; when it reaches `Failures` **and** currently installed,
    `remove()`, `installed = false`, log loudly "resolver unhealthy — BYPASS: DNS falling back to direct".
- **ctx.Done**: `remove()` (idempotent) so a shutdown never leaves a wedging redirect behind.

The consecutive-failure threshold is the flap guard: a single dropped probe does not bypass. Restore is
immediate on the first success (asymmetric: fail slowly, recover fast — a working resolver should re-cover
unconfigured clients as soon as it can).

## The default probe

`defaultProbe(port int) func() bool`: dial `127.0.0.1:port` UDP, send a well-formed DNS query for a fixed
innocuous name, wait for **any** response within a short timeout (e.g. 1s). A response — NXDOMAIN (blocked)
or a relayed upstream answer — proves the resolver is reading and answering. No response → the resolver is
wedged or its whole resolution path (incl. upstream) is dead; either way removing the redirect and letting
the client resolve directly is the safe move. (An upstream-independent sentinel probe is the stated
follow-up; coupling to the upstream is acceptable because a dead upstream means resolution is broken through
us regardless, so bypassing is still correct.)

## Wiring

In `applyDNSSink`, when `OPENSHIELD_DNS_REDIRECT=1`, replace the direct `dnsredirect.Install(...)` +
`Remove-on-ctx` with `(&dnsredirect.Watchdog{Port: port, Mark: mark, Log: log}).Run(ctx)` in a goroutine.
The Watchdog now owns install/remove; the failure-to-install case is handled inside it (logged, keep
running).

## Testing

- **(A) unit, no root** — the state machine with fake `probe`/`install`/`remove` hooks and a manually
  driven tick (extract the tick logic into `step()` so the test does not depend on real time):
  - `Failures = 3`: two failures do NOT remove; the third does (exactly one remove) — **the threshold is
    load-bearing**.
  - after a bypass, a success re-installs exactly once and resets the counter.
  - ctx-done removes.
  - **Mutation**: bypass after 1 failure instead of `Failures` → the "two failures do not remove" assertion
    FAILs. Revert.
- **(B) gated real-kernel VM test** (`requireRoot`, self-contained on loopback): a canned upstream on
  `127.0.0.2:53`; a real sinkhole resolver (blocking `evil.example`) behind a real `Watchdog` with a short
  interval; assert a client query to `127.0.0.2:53` for `evil.example` → NXDOMAIN (redirect active). Then
  **kill the resolver**; after the watchdog bypasses, the same `evil.example` query now reaches the real
  `127.0.0.2:53` upstream directly → NOERROR (the sinkhole bypassed, resolution NOT wedged). `Run` exits on
  ctx cancel and the redirect is gone. Build on the VM (`go test -c` + scp + `sudo`); paste the PASS.
