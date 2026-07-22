# observability delta

## ADDED Requirements

### Requirement: The control plane exposes operational counters as Prometheus metrics
The control plane MUST expose its operational counters — dropped, rejected, and gapped telemetry among them — in the Prometheus text exposition format at a metrics endpoint, reflecting the live counter values, with a HELP and TYPE line per metric. The endpoint MUST expose counts only, never subject or content.

#### Scenario: The metrics reflect the live counters
- **WHEN** the metrics endpoint is scraped
- **THEN** it returns the current counter values in valid Prometheus format
