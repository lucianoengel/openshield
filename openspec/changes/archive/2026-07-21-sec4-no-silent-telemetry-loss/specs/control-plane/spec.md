# control-plane delta

## ADDED Requirements

### Requirement: Receive-side message drops are counted, never silent
The control plane MUST install an asynchronous NATS error handler that counts and logs a
dropped message (a slow-consumer overflow above all), and MUST set explicit pending limits on
its subscriptions so an overflow is deterministic and surfaces through that handler rather
than being dropped silently. A receive-side drop MUST increment an observable counter.

#### Scenario: A slow consumer's drops are observed
- **WHEN** a subscription's pending queue overflows under load
- **THEN** the error handler fires, the drop is counted and logged, and it is never a silent loss
