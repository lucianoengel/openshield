## ADDED Requirements

### Requirement: Device posture is keyed end-to-end by one shared canonical pseudonym

The producer MUST publish device posture under the canonical one-way pseudonym of its enrolled
agent identity — never under the raw agent id or an operator-supplied subject — produced by a
SINGLE shared derivation that the gateway's posture roster/verifier and the access proxy also use.
Because the publisher, the signature roster (`keyFor`), the posture store, and the proxy all derive
the subject identically from the agent identity, a posture that verifies and is stored for an agent
MUST be found by the proxy when that same agent's device certificate connects. The derivation MUST
remain one-way (D23): the raw agent identity MUST NOT enter the pipeline, and the reverse mapping
stays a deployer concern behind an audited lookup. Re-keying the subject MUST NOT weaken SEC-12 — an
update is still applied only if it verifies against the reporting agent's own enrolled key, now
resolved under the canonical pseudonym.

#### Scenario: Posture published by the real producer is found for that agent's device

- **WHEN** the producer publishes a signed compliant posture for an enrolled agent through the real
  publish path, and the gateway verifies and stores it
- **THEN** a request presenting that agent's device certificate resolves device posture as PRESENT,
  with no test seeding the posture store under a literal it then reads back

#### Scenario: Keying posture by the raw agent id is not found (mutation guard)

- **WHEN** the producer instead publishes posture under the raw agent id rather than the canonical
  shared pseudonym
- **THEN** the gateway store holds it under a key the proxy never queries, the proxy resolves posture
  as ABSENT, and a policy requiring an attested device fails the connection closed — so reverting the
  fix flips the end-to-end test to FAIL
