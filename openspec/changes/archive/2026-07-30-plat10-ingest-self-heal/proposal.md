# A broker that came back empty wedged the fleet, silently

## Why

Filed as PLAT-10 by D367, which reproduced it and deliberately did not fix it. This is the fix.

`natsx.EnsureTelemetryStream` was called from exactly two places — `controlplane.Run` and the producers'
`UseJetStream` — **both at process startup**. So a broker that came back without the stream stayed without
it:

- every agent's publish failed with `no response from stream`, forever;
- the control plane's durable push consumer had been deleted along with the stream, so it received nothing
  and **said nothing at all**;
- every agent's spool grew to `OPENSHIELD_QUEUE_MAX` and began dropping the **oldest** records.

Measured: rows frozen for 30s+ while the agent published every 500ms. A broker restarted *with* its store
recovers fully (2 → 120 rows), which is what makes this a specific defect rather than a general outage story.

Ordinary ops produces it: `podman rm` and recreate the broker, or an orchestrator rescheduling it onto fresh
storage.

A silent fleet-wide telemetry outage is a direct D31 violation, and D31 is why the rest of this product is
trustworthy.

## What changes

`Server.healIngest` — a poll (15s) that checks the durable consumer, and on finding it or its stream gone:
logs that ingest is DOWN, recreates the stream, and resubscribes. Repairs and repair *failures* are both
counted and logged.

`subscribeSignedDurable` is extracted from `Run` so the repair builds the subscription from the same code
rather than a second copy that would drift on the first edit. `sigSub` moves out of the `subs` slice into
its own field, because it is the one subscription that can be replaced while the server runs.

## Impact

- Behaviour change: the control plane now recovers from a broker losing its state instead of requiring a
  restart, and one `ConsumerInfo` round trip every 15s.
- No new dependency, no proto change, no migration.
- Affected capability: **event-transport**.

## Design choices worth stating

**A poll, not a reconnect handler.** The reconnect hook was the obvious place and it is not enough: a stream
can be deleted while the connection stays perfectly healthy — an operator with `nats stream rm`, a
misconfigured retention, a cluster losing the asset without dropping TCP. No disconnect occurs, so no
handler fires. One timer covers that case and the reconnect case, and cannot miss an edge nobody thought to
enumerate.

**The repair is narrow on purpose.** Only `ErrConsumerNotFound` or `ErrStreamNotFound` triggers it. Any
other error — a timeout, a transient cluster error — leaves the subscription alone, because rebuilding a
working consumer on every blip is a worse failure than the one being fixed.

**It announces before it repairs**, so the log shows ingest went down even when the repair then fails.

## Honest limits

- **Records published into the gap are gone.** They were refused by a broker with no stream, not buffered by
  it. Recovery depends on producers having spooled them (D40/D67) and re-sending. This heals the channel,
  not its contents — and the log says so rather than implying a clean recovery.
- **Up to one poll interval of ingest is lost** on top of the reconnect. Bounded and visible, not zero.
- **The engine and gateway are not covered.** They publish; their sends will fail until *something*
  recreates the stream, which the control plane now does. So the fleet recovers, but a deployment running
  producers with no control plane reachable would not — that configuration is already broken for other
  reasons, and this change does not make it worse.
- The stream config is a constant, so a repair recreates the stream with the ORIGINAL settings. If an
  operator had deliberately tuned the stream, the repair overwrites that intent. Recorded rather than
  guarded: the alternative is refusing to heal, which is where this started.
