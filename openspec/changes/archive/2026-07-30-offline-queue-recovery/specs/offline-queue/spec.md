## ADDED Requirements

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
