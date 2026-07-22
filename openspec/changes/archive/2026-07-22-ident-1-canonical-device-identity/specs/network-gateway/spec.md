## MODIFIED Requirements

### Requirement: The access proxy enriches decisions with published device posture, unattested devices fail closed
The gateway MUST subscribe to published device-posture updates and record each into a posture store, and
the access proxy MUST enrich each request's decision context with the connecting subject's posture. The
proxy MUST resolve posture under the SAME shared canonical device-pseudonym derivation the producer
publishes under and the roster verifies under — it MUST NOT derive the posture-lookup subject by any
independent or divergent scheme, so a device whose posture arrived through the real producer path is
actually recognized. A subject with published posture MUST carry it (marked present); a subject with NO
published posture MUST keep posture absent, so a policy requiring an attested device denies it (the
tamper-lockout). A malformed posture update MUST be rejected, not silently ignored.

#### Scenario: A compliant device is allowed and an unattested device is denied
- **WHEN** a policy requires an attested device, and a subject has posture published for it through the
  real producer path (keyed by the shared canonical pseudonym of its enrolled agent identity)
- **THEN** the connecting device certificate for that agent resolves posture as present and is allowed;
  and a device whose agent has no published posture is denied
