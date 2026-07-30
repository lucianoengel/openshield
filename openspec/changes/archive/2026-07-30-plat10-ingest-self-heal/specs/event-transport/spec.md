## ADDED Requirements

### Requirement: The telemetry consumer MUST be kept alive, not merely created at startup

The control plane SHALL detect that its durable telemetry consumer or its stream has gone, SAY SO, and
rebuild both — for as long as it runs, not only when it starts.

The stream was created in exactly two places, both during process start, so a broker that returned without
it stayed without it. Every producer's publish was refused, the durable consumer had been deleted with the
stream, and the control plane reported nothing at all while each producer's spool grew to its ceiling and
began dropping the oldest records. Ordinary operations produce this: recreating the broker container, or an
orchestrator moving it onto fresh storage.

The check SHALL be periodic rather than tied to a reconnect. A stream can be deleted while the connection
stays healthy — an operator removing it, a misconfigured retention, a cluster losing the asset without
dropping TCP — and no reconnect happens, so a reconnect hook cannot see it.

The repair SHALL be NARROW. Only a missing consumer or a missing stream may trigger it; any other error
leaves the subscription alone, because tearing down a working consumer on a transient failure is a worse
outcome than the one being fixed.

The loss SHALL NOT be overstated. Records published while the stream was absent were REFUSED by the broker,
not buffered by it; they return only as producers drain their own offline spools. This heals the channel,
not its contents.

#### Scenario: A broker that returns with empty state does not wedge the fleet
- **WHEN** the broker comes back with no JetStream state
- **THEN** the stream and the durable consumer are rebuilt, and producers' spooled records are stored

#### Scenario: Ingest going down is announced before it is repaired
- **WHEN** the consumer is found to be missing
- **THEN** the control plane logs that telemetry ingest is down, before attempting the repair, so the event
  is visible even if the repair then fails

#### Scenario: A failed repair is not silent
- **WHEN** the stream cannot be recreated or the resubscribe fails
- **THEN** that is logged and counted, and retried

#### Scenario: A transient error does not rebuild a working consumer
- **WHEN** the consumer check fails for a reason other than a missing consumer or stream
- **THEN** the existing subscription is left in place

#### Scenario: No self-healing is caught
- **WHEN** the healing loop does not run
- **THEN** the scenario fails because the spool never drains after an empty-state broker returns
