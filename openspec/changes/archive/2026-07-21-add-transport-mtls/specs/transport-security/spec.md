# transport-security

## ADDED Requirements

### Requirement: The agent-facing channels support mutual TLS
The enrollment endpoint and the telemetry transport MUST support TLS with MUTUAL authentication —
the server verifying the agent's client certificate and the agent verifying the server's certificate
against a configured CA — so that the channel is confidential and both peers are authenticated, not
only the message payload.

This is a channel-security layer BENEATH Ed25519 message signing (D50), which is unchanged. Signing
proves per-message attribution; TLS authenticates the peer and hides the wire. The enrollment token
and telemetry are no longer readable or capturable on the wire.

#### Scenario: Enrollment and telemetry succeed over mutual TLS
- **WHEN** TLS is configured on the server and an agent with a CA-issued client certificate enrolls
  and publishes telemetry
- **THEN** the handshake authenticates both peers, enrollment succeeds, and the telemetry is received
- **AND** the fleet e2e asserts the round trip over mTLS

### Requirement: An unauthenticated peer is refused, never downgraded
With TLS enabled the server MUST refuse a peer that presents no valid client certificate and MUST NOT
fall back to plaintext, so an on-path or rogue peer cannot open the channel or capture a token.

A silent downgrade to plaintext would reintroduce the exact gap TLS closes, so there is no
try-TLS-then-plaintext path: a failed or wrong-CA handshake is a refusal.

#### Scenario: A client without a valid certificate is refused
- **WHEN** TLS is enabled and a client without a CA-issued certificate attempts to enroll or connect
- **THEN** the handshake fails and no enrollment or telemetry is accepted
- **AND** a test asserts the connection is refused rather than served in plaintext

### Requirement: TLS is opt-in and off by default
Transport TLS MUST be disabled unless explicitly configured with CA and certificate material, so the
local dev loop and existing plaintext tests are unchanged and enabling encryption is a deliberate
operator act.

#### Scenario: Unconfigured transport stays plaintext
- **WHEN** no TLS configuration is provided
- **THEN** the enrollment endpoint and telemetry transport operate exactly as before, in plaintext
- **AND** a misconfiguration (unreadable or mismatched cert material) fails loudly at startup rather
  than silently serving plaintext

### Requirement: TLS does not replace message signing
A TLS-authenticated peer's telemetry MUST still be verified by signature, so channel authentication
and message attribution remain independent and both are enforced.

Neither layer is trusted to do the other's job: a valid client certificate does not make a
badly-signed message acceptable, and a valid signature cannot arrive over a failed handshake.

#### Scenario: A cert-authenticated but badly-signed message is still rejected
- **WHEN** a peer completes the mutual-TLS handshake but sends telemetry that fails signature
  verification
- **THEN** the message is rejected and counted exactly as an unverified message is (D50)
- **AND** a test asserts the two layers are not conflated
