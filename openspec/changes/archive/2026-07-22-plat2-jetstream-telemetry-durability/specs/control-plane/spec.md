## ADDED Requirements

### Requirement: Durable telemetry ingest acknowledges only after persistence

When durable ingest is enabled, the control plane MUST acknowledge a signed-telemetry message only
AFTER it has been persisted or terminally rejected — never before — so a consumer restart or a slow
persist does not lose verified telemetry (the message remains redeliverable until acknowledged). A
TRANSIENT failure (an infrastructure/database error) MUST negatively-acknowledge the message so it is
redelivered, not dropped. A PERMANENT outcome — a bad signature, an unknown or revoked agent, or a
redelivered message whose sequence was already applied (a replay, handled idempotently) — MUST be
acknowledged as terminal and counted, so a permanently bad or duplicate message is not redelivered
forever. The per-message verification MUST serialize concurrent messages for the SAME agent (for the
monotonic-sequence check) without holding the agent-identity row lock across the whole transaction.

#### Scenario: A persisted message is acked, a transient failure is redelivered, a replay is not looped
- **WHEN** durable ingest is enabled and, in turn, a valid message is persisted, a message hits a transient persist failure, and an already-applied message is redelivered
- **THEN** the persisted message is acknowledged, the transient one is negatively-acknowledged and later redelivered (not lost), and the already-applied replay is acknowledged as terminal and counted rather than redelivered forever — and concurrent messages for one agent still enforce the monotonic sequence
