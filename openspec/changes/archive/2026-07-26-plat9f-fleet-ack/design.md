## Context

D269 publishes signed fleet controls over best-effort pub/sub. Nothing reports back.

## Goals / Non-Goals

**Goals:** acknowledgement over the existing channel; actual state, not instructed state; an indexed
summary.

**Non-Goals:** guaranteed delivery; absence detection; a per-agent endpoint.

## Decisions

### The acknowledgement rides the heartbeat

The heartbeat already flows from every agent, already proves liveness, and already has a home in the
aggregate. Building an acknowledgement transport would add a connection, a retry policy and a failure mode
to answer a question the existing signal can carry in two fields.

Same discipline that put the response-intent id on `Context.Version` rather than a new hashed ledger
column (D254), and read SOAR-5's observables from the event that already carried them.

### Report ACTUAL state, not instructed state

The obvious implementation is "the control plane knows what it sent, so it knows who should be disabled".
That is wrong in the direction that matters: it cannot see an agent disabled by its **local** break-glass
file, which is precisely the path used when the control plane is unreachable. Asking the agent what it is
actually doing costs one boolean and answers both cases.

### A projection, not a payload scan

Heartbeat payloads live in the aggregate as bytes. Answering "who is still enforcing?" by decoding all of
them would make an operational question cost a table scan. The projection is upserted on each heartbeat —
latest wins, because an agent's *current* state is what is being asked about.

### Silence is not compliance, and the code must not imply otherwise

The summary counts only agents that have reported. It would be easy — and wrong — to treat a missing agent
as enforcing (flattering) or as disabled (alarming). Both invent a fact. Absence already has a mechanism
(D50/D51 overdue), and the honest limit is stated where the summary is defined.

## Risks / Trade-offs

- **Point-in-time** → an agent can change state between heartbeats; the report is as fresh as the
  heartbeat interval, and no fresher.
- **A compromised agent can lie** → it can already lie about everything else; this adds no new trust.

## Migration Plan

Additive proto fields and one table. A fleet whose agents predate the fields reports zeros, which is
accurate: they have not told us.

## Open Questions

- Whether the summary should expose per-agent detail or stay aggregate — aggregate for now, since the
  operator question during an incident is "how many are still enforcing?", not "which one is host 47".
