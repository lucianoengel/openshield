# policy-evaluation (delta)

## ADDED Requirements

### Requirement: Ready-made compliance policy packs are selectable
The policy layer MUST provide ready-made compliance packs (at least PCI, HIPAA, and GDPR) as
selectable policies, each alerting when a detector in that regulation's scope is present and allowing
otherwise, observe-only (alert, not block). Selecting an unknown pack MUST be an error, never a
silent fallback to a permissive policy, and the pack's identity MUST be stamped on the resulting
decision.

#### Scenario: A pack alerts on its scope and an unknown pack is refused
- **WHEN** a compliance pack evaluates data in its regulatory scope, data outside its scope, and a binary is configured with an unknown pack name
- **THEN** the in-scope data alerts, the out-of-scope data is allowed, and the unknown pack name is refused rather than silently applying a permissive policy
