# offline-queue Specification

## Purpose
The agent telemetry store-and-forward: a bounded, durable, FIFO disk queue wrapping any Transport, so an offline agent never silently drops a payload — held on disk, delivered in order on reconnect, and overflow drops oldest as a loud audit event (no silent loss, bounded guarantee).
## Requirements
### Requirement: An unreachable control plane never silently drops a payload
When the inner transport is unreachable, the queueing transport MUST persist the payload durably
and MUST NOT drop it silently. A payload accepted while offline MUST survive a process restart.

For a product whose only honest claim is a trail of what it saw, losing that trail on a network
blip is the failure the whole system exists to prevent (D1, D31). Held-on-disk is the difference
between "delivery is pending" and "the event never happened".

#### Scenario: Payloads produced while offline are delivered on reconnect, in order
- **WHEN** the control plane is unreachable, several payloads are published, then it returns and
  Flush runs
- **THEN** every payload is delivered, in the order it was produced
- **AND** a test drives offline→online and asserts completeness and FIFO order

#### Scenario: The queue survives a restart
- **WHEN** payloads are queued offline and the queue is reopened from the same directory
- **THEN** the queued payloads are still present and drain in order
- **AND** a test reopens the spool and asserts nothing was lost

#### Scenario: A torn write cannot corrupt the queue
- **WHEN** a payload file is written
- **THEN** it appears atomically (complete or absent), so a crash mid-write leaves no partial record
- **AND** the drain path skips or is never given a partial file

### Requirement: The queue is bounded and overflow is a loud event
The queue MUST have a maximum size and, on overflow, MUST drop the oldest payload and invoke an
overflow callback so the drop is recorded as a high-severity audit event. It MUST NOT grow without
limit and MUST NOT drop silently.

An unbounded spool is a disk-exhaustion DoS; a silent drop is indistinguishable from nothing
happening (D17). The honest guarantee is "no silent loss", not "no loss" — a bounded queue that
overflows has lost data, and that fact must be recorded, not hidden.

#### Scenario: Overflow drops oldest and fires the callback
- **WHEN** the queue is at its ceiling and another payload is enqueued
- **THEN** the oldest payload is dropped, the overflow callback is invoked, and the new payload is
  retained
- **AND** a test fills past the ceiling and asserts the drop, the callback, and that the newest
  payload survived

### Requirement: Callers use the same interface
The queueing transport MUST implement `core.Transport` so existing callers are unchanged, and a
payload published while the control plane is reachable and the queue empty MUST go directly without
touching disk.

The transport seam was shaped so a durable implementation substitutes without changing callers. If
using the queue meant a different interface, every call site would have to know about offline mode,
which is the coupling the seam exists to avoid.

#### Scenario: Online with an empty queue publishes directly
- **WHEN** the inner transport is reachable and the queue is empty
- **THEN** the payload is published directly and no file is written
- **AND** once anything is queued, subsequent payloads queue behind it to preserve order

### Requirement: The durable spool has a production caller
The durable offline queue MUST be wired into the running agent, so the offline-capable principle (D1)
is realized rather than only unit-tested. The agent flushes the spool as connectivity allows, and a
bounded-queue overflow eviction MUST be surfaced loudly (no silent loss, D31).

#### Scenario: The fleet agent spools and flushes, and overflow is loud
- **WHEN** the fleet agent runs with a queue directory configured and the control plane is intermittently
  unreachable
- **THEN** telemetry is spooled during the outage and flushed when reachable, and an overflow eviction
  fires a high-severity log
- **AND** a test asserts the wiring flushes and that overflow is reported, not silent

### Requirement: A spooled outage must DRAIN when the broker returns

Verification SHALL prove that records held on the spool during a broker outage are re-sent and STORED
once the broker is back, not merely that they were spooled.

The claim is "spool when unreachable and re-send on reconnect, so an outage causes a gap, not silent
loss" (D40/D67). Only the first clause was asserted: a scenario stopped the broker and checked the spool
became non-empty, and no scenario ever brought a broker BACK. So `Queue.Drain`, `SignedPublisher.Flush`
and the NATS reconnect they depend on ran in no end-to-end test — the gap was proven and the filling in
was not.

The assertion SHALL be that the spool becomes EMPTY, because `Queue.Drain` removes a record only after
its send succeeds and stops at the first failure keeping the rest; an emptied spool is therefore proof
of delivery, and proof that does not encode the on-disk format. A row-count increase alone is NOT
sufficient — the agent keeps producing after recovery, so that is satisfied by an agent which discarded
every spooled record and resumed.

Delivery and storage SHALL be treated as distinct milestones. An empty spool means the broker accepted
the records; the row appears only once the control plane has consumed them off the stream. Asserting the
count at the instant the spool empties is a race, and its failure text reads exactly like the
catastrophic version of the bug.

#### Scenario: Records held during an outage are stored after it
- **WHEN** the broker is taken away while an agent with a spool keeps producing, and is then restored
- **THEN** the spool drains to empty
- **AND** at least as many rows as were held appear in storage

#### Scenario: A drain that does not happen is caught
- **WHEN** the flush path is disabled
- **THEN** the scenario fails on the spool never emptying

### Requirement: Taking the broker away and bringing it back must be distinguishable from replacing it

The harness SHALL be able to restore a broker with its JetStream state intact AND to bring one back with
empty state, because the two produce completely different product behaviour and conflating them hides a
defect.

A restart with state recovers fully. A broker with a fresh store never recovers: the telemetry stream is
created only at process startup, so nothing recreates it, and the control plane reports nothing at all
while every agent's spool grows toward its ceiling and begins dropping the oldest records. A restore
helper that silently did the second would make the recovery scenario fail for a reason unrelated to
draining.

#### Scenario: A restored broker keeps its stream
- **WHEN** the broker is restored with its JetStream store
- **THEN** the telemetry stream is still present and ingest resumes

#### Scenario: An empty-state broker is a separate, named condition
- **WHEN** a broker returns with no JetStream state
- **THEN** that is a distinct helper and a recorded defect, not the recovery path under test

### Requirement: An endpoint whose OWN network vanishes must recover, not just one whose broker stops

Verification SHALL include a scenario in which the AGENT is partitioned — its network interface removed and
later restored on a different address — as distinct from a scenario in which the broker is stopped.

The two are not interchangeable, and a client that handles the second need not handle the first. A stopped
broker sends a RST and the client knows at once. An endpoint whose interface disappears is left holding a
TCP connection that is dead and looks open: nothing arrives to invalidate it, so until a keepalive times out
the client still reports connected, does not reconnect, and every attempt to drain the spool fails while the
spool keeps growing. DNS goes with the interface, so the broker's name stops resolving. On rejoin the
endpoint has a different address.

This is also the outage endpoints actually experience most: a closed laptop, a dropped VPN, a radio switched
off.

#### Scenario: A partitioned agent recovers when its network returns
- **WHEN** an agent's network interface is removed while it keeps producing, and later restored on a
  different address
- **THEN** the records held during the partition are delivered and stored

#### Scenario: A dead-but-open connection is detected in seconds, not minutes
- **WHEN** the connection is silently dead because the interface went away
- **THEN** the client notices within tens of seconds and begins reconnecting, rather than waiting out a
  multi-minute keepalive budget during which it neither delivers nor recovers

#### Scenario: A keepalive budget long enough to strand the spool is caught
- **WHEN** the keepalive interval is left at a multi-minute default
- **THEN** the scenario fails because the spool does not drain after the network returns
