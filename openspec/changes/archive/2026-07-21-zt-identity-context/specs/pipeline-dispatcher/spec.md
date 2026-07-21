# pipeline-dispatcher delta

## ADDED Requirements

### Requirement: The pipeline Context carries typed identity and device posture
The enrichment Context MUST carry a verified pseudonymous identity, an authorization role, and a device
posture as TYPED fields (never an open map), resolved via the existing context-resolution hook. The
device posture MUST distinguish "not computed" from "computed and compliant" with an explicit presence
flag, so that absent posture is visible to policy and is never silently treated as compliant.

#### Scenario: Identity, role, and posture reach policy through the unchanged dispatcher
- **WHEN** a context resolver supplies an identity, role, and device posture for an event
- **THEN** the policy stage receives them and can decide on them, with no change to the dispatcher,
  State, Stage, or Enforcer interfaces
