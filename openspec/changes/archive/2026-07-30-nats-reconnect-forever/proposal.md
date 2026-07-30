# Every long-lived process gave up on the broker after two minutes

## Why

nats.go defaults to `MaxReconnects=60` with `ReconnectWait=2s`. That is a budget of roughly **two
minutes**, after which the client closes the connection permanently — the process keeps running and never
publishes or receives again.

**No process in this product passed a single reconnect option.** The engine and gateway had a
`natsOptions(log)` helper that returned `nil` unless TLS was configured, so the common path ran on the
defaults. The fleet agent built its options the same way. The control plane appended only an
`ErrorHandler`.

Measured end to end, on the same broker restored to the same port with its state intact:

| Outage | Result |
| --- | --- |
| 4 seconds | recovers fully — 2 → 120 rows stored |
| 150 seconds | **never recovers**; still 2 rows thirty seconds after the broker is back |

The consequence differs by process and none is acceptable:

- The **agent** keeps producing into the durable spool that exists so an outage causes a gap rather than
  silent loss (D40/D67) — and can now never drain it. The spool fills to `OPENSHIELD_QUEUE_MAX` and starts
  **dropping the oldest records**, so a bounded outage silently becomes unbounded evidence loss. The
  feature defeats itself.
- The **control plane** stops consuming. That is not one endpoint going quiet, it is the whole fleet's
  ingest, with the server still running and reporting nothing wrong.
- The **engine** and **gateway** stop publishing decisions, so enforcement keeps happening and the record
  of it does not.

Two minutes is not a long outage. A laptop closed over lunch, a switch reboot, a VPN drop, a broker
upgrade.

This was found by the offline-queue recovery work (D367), which named the reconnect budget as the next
thing to measure rather than assuming either way.

## What changes

`natsx.ResilienceOptions(onEvent)` — one policy, used by every long-lived caller:

- `MaxReconnects(-1)` — infinite. This is the fix; the rest is hygiene around it.
- `ReconnectWait(2s)` + `ReconnectJitter(1s, 4s)` — a fleet on one fixed interval reconnects in lockstep
  and stampedes the broker that just came back.
- `DisconnectErrHandler` / `ReconnectHandler` logging. Until now a disconnected agent said nothing about
  being disconnected; the only hint was a periodic `flush stopped after 0 (still unreachable?)` from the
  spool drain, which reads as a spool problem rather than a connectivity one (D31).

Wired into the fleet agent, the engine, the gateway, and `controlplane.Run` — deliberately **not**
`controlplane.Connect`, which exists for operator subcommands that publish one message and exit, where
giving up promptly is correct and retrying forever would hang a CLI.

`TestAnOutageLongerThanTheReconnectBudgetStillRecovers` proves it: 80 records held across a 200-second
outage, all recovered.

## Impact

- Behaviour change, and it is the point: these processes no longer stop trying.
- No new dependency, no proto change, no migration.
- Affected capability: **event-transport**.

## Honest limits

- **Infinite retry is a policy choice, not a free win.** A process that can never give up will also never
  exit on its own if the broker is gone forever; it will sit there retrying and spooling. For a daemon
  whose job is to keep reporting that is correct, and the spool's own ceiling bounds the disk cost — but
  it does mean "the agent is running" stops implying "the agent is connected". The disconnect log line is
  what makes that visible, and the fleet-side dead-man's-switch is what makes it actionable.
- **This does not fix PLAT-10.** A broker that returns with empty JetStream state still wedges the fleet:
  the client reconnects, and the stream it needs is not there. Reconnecting forever is necessary and not
  sufficient.
- The scenario is slow by construction (~3.5 min) because it has to outlast the budget it is testing.
