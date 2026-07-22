## MODIFIED Requirements

### Requirement: Authenticated webhook body
A webhook sink MUST optionally authenticate its payload so a receiver can verify an alert genuinely
came from this control plane, was not tampered with, and is not a replay. When a signing secret is
configured, the webhook MUST send an `X-Openshield-Signature: sha256=<hex>` header whose value is the
HMAC-SHA256 of the timestamped payload (`"<unix-ts>." + body`), together with an
`X-Openshield-Timestamp` header carrying that timestamp; verification MUST use a constant-time
comparison AND MUST reject a signature whose timestamp is outside a freshness window (stale or
implausibly far in the future), so a captured signed delivery cannot be replayed indefinitely. When no
secret is configured, the webhook MUST send no signature or timestamp header and the body MUST be
byte-for-byte unchanged. Each sink MAY use its own secret, so a captured delivery for one sink does not
authenticate at another.

#### Scenario: A signed body verifies and a tampered body is rejected
- **WHEN** a webhook is configured with a secret and posts a notification
- **THEN** the request carries an `X-Openshield-Signature` header over the timestamped body that verifies with the same secret, while a tampered body or a wrong secret fails verification

#### Scenario: A stale replay is rejected
- **WHEN** a previously-valid signed delivery is presented again after the freshness window has passed
- **THEN** verification rejects it because its timestamp is stale, even though the HMAC over the body still matches
