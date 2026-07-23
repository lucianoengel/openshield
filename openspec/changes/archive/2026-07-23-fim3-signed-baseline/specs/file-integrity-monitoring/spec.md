## ADDED Requirements

### Requirement: The baseline can be operator-signed and verified before it is trusted

The system SHALL support an operator-signed baseline: the operator signs the baseline manifest with a
private key, and a node configured with the corresponding trusted public key MUST verify the signature
before trusting the manifest. Verification MUST be fail-closed — a malformed envelope, a missing or
invalid signature, or a signature from a different key MUST be refused and MUST yield no manifest — and
MUST happen before the manifest is used. The signature MUST be domain-separated so a signature minted for
the baseline cannot validate for any other purpose in the system, and vice-versa. The node MUST hold only
the public key; it MUST NOT sign its own baseline.

#### Scenario: A validly-signed baseline is accepted
- **WHEN** a baseline signed by the operator key is loaded with the matching trusted public key
- **THEN** the manifest is accepted and used

#### Scenario: A tampered signed baseline is refused
- **WHEN** a signed baseline's manifest bytes are altered after signing, or its signature is from a different key
- **THEN** verification fails and the manifest is refused (no manifest is returned)

### Requirement: Verification is required when a trusted key is configured

When a trusted operator public key is configured, the system MUST load the baseline only via signature
verification: an unsigned or unverifiable baseline MUST be a fatal configuration error, and the node MUST
NOT capture and trust its own baseline. When no trusted key is configured, the system MAY load an
unsigned baseline for backward compatibility, but MUST loudly warn that an unsigned baseline is
tamper-vulnerable.

#### Scenario: An unsigned baseline is refused when a key is required
- **WHEN** a trusted public key is configured but the baseline is unsigned or does not verify
- **THEN** the system refuses to run on that baseline (a fatal configuration error)

#### Scenario: The unsigned path is warned when no key is configured
- **WHEN** no trusted public key is configured and an unsigned baseline is loaded
- **THEN** the load proceeds but a warning states that the unsigned baseline is tamper-vulnerable
