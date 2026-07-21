# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier loads operator-authored custom rules only when signed and verified
The classifier MUST accept custom detector rules only from a bundle whose Ed25519 signature
verifies against a trusted operator key; an unsigned, tampered, wrong-key, or malformed
bundle MUST load no rules and MUST return an error (fail-closed). A rule MUST be declarative
— a regex pattern plus a named built-in validator, never executable code — and a rule that
does not compile or is out of bounds MUST fail the entire bundle rather than load partially.
A custom rule MUST report the generic custom detector type, never a per-rule name, so it
cannot leak what it detects.

#### Scenario: A signed bundle loads and an untrusted one does not
- **WHEN** an operator-signed rule bundle is loaded with the trusted key
- **THEN** its custom rules fire (reported as the generic custom type) alongside the built-ins; and a wrong-key, tampered, or unsigned bundle loads nothing and errors
