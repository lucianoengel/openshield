## ADDED Requirements

### Requirement: A transparent inline mode intercepts and decides a redirected flow at L4

The system SHALL provide an opt-in transparent inline mode that accepts a TCP flow redirected to it
(TPROXY), recovers the flow's ORIGINAL destination from the accepted connection, and decides the flow
through the pipeline on its metadata (source and original destination). A flow the pipeline blocks SHALL
be dropped — the client connection is closed and no bytes reach the destination. A flow the pipeline
allows SHALL be spliced bidirectionally to its original destination, so an allowed flow is transparent
to both endpoints. The transparent mode SHALL be off by default (an inline data-plane is an explicit
deploy choice).

#### Scenario: A flow to a blocked destination is dropped
- **WHEN** a redirected flow's original destination is one the pipeline blocks
- **THEN** the connection is dropped and no data is forwarded to the destination

#### Scenario: A flow to an allowed destination is spliced through
- **WHEN** a redirected flow's original destination is one the pipeline allows
- **THEN** the flow is connected to that destination and data passes in both directions

### Requirement: The inline data-plane preserves egress fail-open

The transparent inline mode MUST fail open: a pipeline error while deciding a flow MUST forward the flow
to its original destination rather than drop it, so a detection failure degrades to a passive wire and
never becomes a network outage. If the transparent listener cannot be created (for example, without the
required network-admin capability), the system MUST fail to WIRE — log the condition and continue
running the rest of the gateway — and MUST NOT take the network down because inline could not arm.

#### Scenario: A pipeline error forwards the flow
- **WHEN** deciding a redirected flow returns an error
- **THEN** the flow is forwarded to its original destination (fail-open), not dropped

#### Scenario: An un-armable inline plane does not break the gateway
- **WHEN** the transparent listener cannot be created
- **THEN** the condition is logged and the gateway continues without the inline plane, forwarding nothing to a blackhole
