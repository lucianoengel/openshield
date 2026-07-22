# agent-process-boundary (delta)

## ADDED Requirements

### Requirement: In-process connector parsers contain a panic to one input
The engine MUST recover from a panic raised while parsing one attacker-influenced input in-process (a network datagram, an audit record, or an event in its processing loop), dropping and counting that input and continuing, so a crafted metadata input cannot crash the engine. This keeps the RCE-prone content parsing in the sandboxed worker unchanged (D29/D35).

#### Scenario: A crafted input that panics a parser does not crash the engine
- **WHEN** an in-process connector parse loop handles an input that panics its parser or sink
- **THEN** the panic is recovered, the input is dropped and counted, and the loop continues to process subsequent inputs
