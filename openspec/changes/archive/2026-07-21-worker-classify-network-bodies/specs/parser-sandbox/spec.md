# parser-sandbox delta

## ADDED Requirements

### Requirement: The worker classifies inline content supplied by a network-capable caller
The worker MUST accept a classify request whose subject is inline content (bytes the caller already
holds) in addition to a file path, and MUST classify it through the same bounded reader — the same
max_bytes ceiling and truncated flag — that the file path uses. A request carrying no subject MUST be
an error, never a clean empty result. This keeps the parser (the RCE surface) inside the seccomp,
no-network sandbox regardless of which node holds the bytes, so a caller that must hold content to do
its job (a network gateway) never runs the parser in its own process.

#### Scenario: Inline content carrying a CPF is classified in the worker
- **WHEN** the worker receives a classify request whose subject is inline content containing a valid CPF
- **THEN** the response carries a CPF detector hit and no matched text

#### Scenario: Empty inline content is a clean no-hit result, not an error
- **WHEN** the worker receives a classify request whose inline content is empty
- **THEN** the response carries no hits and no error

#### Scenario: Inline content over the ceiling is truncated, not exhausted
- **WHEN** inline content exceeds the request's max_bytes
- **THEN** the worker reads only up to the ceiling and reports truncation
