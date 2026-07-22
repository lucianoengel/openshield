# endpoint-engine (delta)

## ADDED Requirements

### Requirement: The engine runs an optional DNS source into the pipeline
The engine MUST be able to run the DNS query connector as an additional event source, enabled by
configuration. When enabled, it MUST bind the DNS listener and feed each parsed query — as a
network Event carrying the queried name and the source IP — into the same pipeline as file
events, so live resolution runs classify → policy → decide → audit. The DNS source MUST be
additive to file watching and observe-only (it produces events, it does not enforce), and its
producer MUST be tracked so the event stream is not closed while the source is still running.

#### Scenario: A live DNS query flows through the pipeline as a network event
- **WHEN** the engine has the DNS source enabled and receives a query datagram
- **THEN** a network event carrying the queried name and source IP is produced onto the engine's event stream for the pipeline to process, and the source shuts down cleanly with the engine
