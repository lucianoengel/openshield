## ADDED Requirements

### Requirement: The forward proxy inspects the response body

When response inspection is enabled, the system SHALL buffer the response body up to a memory bound,
decode gzip content for classification, classify it through the pipeline as an inbound event, and audit
the decision — while always delivering the exact upstream bytes to the client. A response larger than the
bound MUST be forwarded uninspected (an audited coverage gap, not a refusal), and a read or classification
error MUST forward the response rather than break it (fail open). With inspection disabled, the response
MUST be streamed through unchanged.

#### Scenario: A sensitive response is classified, audited, and delivered

- **WHEN** response inspection is on and an upstream returns a body containing sensitive content
- **THEN** the response is classified and the decision audited, and the client still receives the exact
  upstream response

#### Scenario: An over-cap response is forwarded uninspected

- **WHEN** a response body exceeds the memory bound
- **THEN** it is delivered intact to the client and the uninspected coverage is recorded, not refused

#### Scenario: Inspection disabled leaves the response unchanged

- **WHEN** response inspection is off
- **THEN** the response is streamed through exactly as before
