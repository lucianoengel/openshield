# A partitioned endpoint took four minutes to notice, and the spool grew the whole time

## Why

Every outage scenario in this suite stopped the BROKER. That is "the other end went down". It is not what
an endpoint actually does most often, which is that **its own network disappears** — a closed laptop, a
dropped VPN, a radio switched off.

The two are not interchangeable, and this is the empirical proof. A stopped broker sends a RST; the client
knows immediately. An endpoint whose interface is removed is left holding a TCP connection that is **dead
and looks open**. nats.go's keepalive defaults are `PingInterval=2m` with `MaxPingsOutstanding=2`, so
detection takes **up to four minutes**. Throughout that window the client still reports connected, so it
never reconnects — and every spool drain fails.

Measured, with an agent in a container removed from its podman network: the agent logged **no disconnect
and no reconnect at all**, only

```
flush stopped after 0 (still unreachable?): nats: timeout
```

repeated — and it was still doing that after the network came back. The spool went from 4 records to 76
while the scenario waited.

D368's infinite reconnect does not help here: you cannot reconnect a connection you do not know is broken.

## What changes

- `nats.PingInterval(20s)` + `nats.MaxPingsOutstanding(2)` in `natsx.ResilienceOptions` — detection in
  ~40s instead of ~4 minutes. The cost is one PING per connection per 20s.
- `TestAnEndpointSurvivesItsOwnNetworkVanishing` — the agent runs in a container, is removed from its
  network, and rejoins **on a different IP** (10.89.1.3 → 10.89.1.4 in the run that proved it). The
  spool drains and the held records are stored.
- The disconnect log no longer fires on a clean shutdown. `DisconnectErrHandler` is invoked on a
  deliberate `Close()` too, with a nil error, so every normal exit printed *"broker connection lost
  (\<nil\>) — retrying forever; telemetry is being spooled, not sent"* — false on all three counts.
  Noticed only because it appeared in the shutdown output of a **passing** test.

Result: the scenario went from failing after 208s to passing in 66s, with the log now reading
`broker connection lost (nats: stale connection)` → `broker reconnected to …` → drained.

## Impact

- Behaviour change: one small PING per connection per 20s, and a dead connection is noticed ~6x sooner.
- No new dependency, no proto change, no migration.
- Affected capability: **offline-queue**.

## Honest limits

- **One agent, not a fleet.** This partitions a single endpoint. Cross-node effects at scale — a whole
  segment partitioning and then reconnecting together — are not exercised; the jitter added in D368 is the
  mitigation for that and it remains untested at scale.
- **20 seconds is a chosen number, not a derived one.** Faster detection means more pings and more
  false-positive reconnects on a lossy link; slower means a longer stranded window. 20s is defensible and
  is not optimal for any particular deployment.
- **Clock skew and per-node resource limits remain unproven** — the other two of the four properties the
  enterprise gap assessment named. This closes partition and offline-queue drain.
- The container topology needs a working OCI runtime, and the scenario skips (loudly) when the runtime
  cannot start a container at all — which is not hypothetical, see the CI runtime note in this change.
