# pattern-classifier delta

## ADDED Requirements

### Requirement: The worker loads operator-signed custom rules when configured, fail-closed
The worker MUST load operator-authored custom rules from a configured signed bundle, verified
against a configured trusted public key, and merge them with the built-in detectors. A missing
key, or an unreadable, unsigned, tampered, or wrong-key bundle MUST load no custom rules while
the worker continues to classify with the built-ins — an unverified rule MUST never be loaded,
and a bad optional bundle MUST NOT stop classification.

#### Scenario: A signed bundle applies and a tampered one does not
- **WHEN** the worker is configured with a rule bundle and trusted key
- **THEN** a valid signed bundle's custom detector fires, while a tampered or wrong-key bundle loads nothing and the built-ins still classify
