## ADDED Requirements

### Requirement: Alert delivery to multiple sinks

Alert delivery SHALL support fanning out one notification to multiple sinks, so a
deployer can page one system and archive to another. A fanout delivery MUST attempt
every configured sink even when an earlier sink fails, so one broken sink cannot
suppress delivery to the healthy ones. The fanout MUST report an aggregate failure
when any sink fails so the caller can log it, and MUST classify the aggregate as
permanent only when every failing sink failed permanently.

#### Scenario: one failing sink does not suppress a healthy sink

- **WHEN** a notification is delivered to a fanout of two sinks and the first sink errors
- **THEN** the second sink still receives the notification
- **AND** the fanout returns an aggregate error naming the failure

#### Scenario: retry composes without re-paging a succeeded sink

- **WHEN** each sink is individually wrapped with retry beneath the fanout
- **THEN** a transient failure re-attempts only the failed sink
- **AND** a sink that already succeeded is not delivered to again

### Requirement: Authenticated webhook body

A webhook sink SHALL optionally authenticate its payload so a receiver can verify an
alert genuinely came from this control plane and was not tampered with. When a signing
secret is configured, the webhook MUST send an `X-Openshield-Signature: sha256=<hex>`
header whose value is the HMAC-SHA256 of the exact request body. Verification of the
signature MUST use a constant-time comparison. When no secret is configured, the
webhook MUST send no signature header and the body MUST be byte-for-byte unchanged.

#### Scenario: a signed body verifies with the correct secret

- **WHEN** a webhook is configured with a secret and posts a notification
- **THEN** the request carries an `X-Openshield-Signature` header over the body
- **AND** verifying the body with the same secret succeeds

#### Scenario: a tampered body or wrong secret is rejected

- **WHEN** the body is altered after signing, or verified with a different secret
- **THEN** verification fails

#### Scenario: no secret means no signature

- **WHEN** a webhook is configured without a secret
- **THEN** the request carries no signature header
