# event-contract delta

## ADDED Requirements

### Requirement: An Event can describe a network flow or request, metadata only
The Event contract MUST be able to describe a network flow or L7 request as a target variant carrying
connection/request METADATA only — an opaque flow handle (the enforce target), the 5-tuple, protocol,
and L7 metadata (host, method, path, direction) — and MUST NOT carry the body content, which stays in
the classifying process and never crosses the boundary (D10/D29), as file content stays in the worker.

#### Scenario: A network Event carries metadata, never the body
- **WHEN** a network flow / HTTP request Event is constructed
- **THEN** it carries the flow handle and connection/request metadata and no body content
- **AND** a test confirms the Event type exposes no body/content field
