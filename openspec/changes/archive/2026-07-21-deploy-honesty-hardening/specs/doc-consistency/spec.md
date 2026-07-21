# doc-consistency delta

## ADDED Requirements

### Requirement: The network gateway's NIPS/ZT scope is stated honestly
The documentation MUST state that the network gateway is content-inspection egress DLP, not a network
intrusion-prevention system and not a Zero-Trust enforcement point, because it inspects only proxied
HTTP(S) and authenticates no subject (its subject is a hashed source address). The claim MUST be
phrased as what the system does NOT yet do, and MUST pass the overclaim check.

#### Scenario: The docs do not imply NIPS or ZT enforcement
- **WHEN** the documentation describes the network gateway
- **THEN** it states plainly that identity-aware authorization is roadmap, not built, and the overclaim
  check passes
