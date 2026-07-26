## Why

D269 can publish a fleet-wide disable and cannot tell whether it **arrived**. "Did my disable reach the
fleet?" is the question an operator asks about thirty seconds after issuing one, and best-effort pub/sub
does not answer it — which D269 stated as its own residual rather than leaving to be discovered.

## What Changes

- **The heartbeat carries the acknowledgement.** Two additive fields: whether the agent's enforcement is
  actually disabled, and the highest fleet-control sequence it has applied. No new transport, no new
  connection, no new failure mode — the channel already exists and already proves liveness.
- **It reports ACTUAL state, not what the agent was told.** An agent disabled by its **local break-glass
  file** reports `disabled` too, which the control plane has no other way to learn.
- **A projection table** so "which hosts are still enforcing?" and "which have not caught up?" are indexed
  queries rather than a scan of heartbeat payloads.

## Capabilities

### Modified Capabilities
- `enforcement`: fleet-wide enforcement state is reported back and queryable.

## Impact

- **Proto**: two additive `Heartbeat` fields. **Migration 037**: `agent_enforcement`.
- **Honest scope**: this reports what agents have **told** us. A silent agent contributes nothing, so
  **"no news" is not "still enforcing"** — an agent that is gone looks exactly like one that has not
  checked in. Absence is the overdue mechanism's job (D50/D51) and this must not be read as covering it.
  It is also point-in-time: an agent could change state between heartbeats. No per-agent API endpoint in
  this increment — the summary and the metric are the operator surface.
