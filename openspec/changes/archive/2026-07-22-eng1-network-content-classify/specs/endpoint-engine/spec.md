# endpoint-engine (delta)

## ADDED Requirements

### Requirement: The engine classifies network-carried content in the sandboxed worker
The engine MUST classify the content of a network event that carries a body (an SMTP message) by
sending the bytes to the sandboxed worker as inline content, WITHOUT placing the content in the
Event and without parsing it in the engine itself. The content source MUST be installable after
construction and default to none, so a network event with no content source remains metadata-only
(classified on its metadata), and a file event continues to classify by path (and a pathless file
event continues to fail).

#### Scenario: An SMTP body is classified in the worker while DNS stays metadata-only
- **WHEN** the engine processes a network event whose body is provided by the content source, and separately a network event with no content
- **THEN** the body is classified in the worker and the resulting decision is audited, while the content-less event is classified only on its metadata and a pathless file event still errors
