## ADDED Requirements

### Requirement: An event timestamp that cannot be true MUST NOT be trusted for rhythm analysis

Detection that measures the rhythm of an endpoint's activity SHALL reject an event timestamp dated further
into the future than a configured tolerance, and measure that event by receipt time instead. The fallback
SHALL be counted so it is visible.

An event cannot be observed after it was received, so a future timestamp has no benign reading. Trusting one
lets an endpoint place its own contacts outside the very window meant to catch them.

The tolerance SHALL bound only the FUTURE. A timestamp in the past is what every event spooled while an
agent was offline legitimately has, so bounding the past destroys the detection — measured, it takes beacon
detections from one to zero.

A malformed tolerance SHALL fall back to the default rather than removing the bound.

#### Scenario: A future-dated event is measured by receipt time
- **WHEN** an event is dated beyond the tolerance ahead of its receipt
- **THEN** rhythm analysis uses the receipt time, and the fallback is counted

#### Scenario: A past-dated event is trusted
- **WHEN** an event is dated hours or days before its receipt
- **THEN** its own timestamp is used, because that is what a spooled event looks like

#### Scenario: A missing timestamp is not clock skew
- **WHEN** an event carries no observation time
- **THEN** receipt time is used and it is NOT counted as skew

### Requirement: The limits of trusting an endpoint's clock MUST be recorded

Where detection depends on timestamps an endpoint authors, the product SHALL state what that does and does
not protect against.

Liveness derives from the control plane's own receipt time, so an agent cannot alter its apparent aliveness
by lying about the time. Rhythm analysis necessarily uses the endpoint's own time — measuring by receipt
would measure the transport — so a compromised endpoint that jitters its reported times BACKWARDS is
indistinguishable from one that was merely offline. That is not closable without a time source the endpoint
does not control, and claiming otherwise would be worse than the gap.

#### Scenario: The residual is stated rather than implied
- **WHEN** the clock-skew behaviour is documented
- **THEN** it names backward skew as undetectable here, and why
