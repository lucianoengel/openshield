## ADDED Requirements

### Requirement: The transparent inline mode decides a flow on its TLS SNI

The transparent inline mode SHALL peek the initial bytes of a redirected flow without consuming them,
extract the server name (SNI) from a TLS ClientHello, and decide the flow on that hostname in addition to
its destination IP, so a flow to a policy-blocked domain served from a shared IP is dropped. The SNI
parser MUST be defensive: a buffer that is not a ClientHello, is truncated, has no SNI, or carries an
attacker-crafted length MUST yield no hostname rather than an error or a crash. When the flow is allowed
and spliced, the peeked bytes MUST be replayed to the destination so the flow is byte-for-byte
transparent (the destination sees the original handshake). A flow with no recoverable SNI (non-TLS, a
peek timeout, or a parse miss) MUST fall back to the destination-IP decision and MUST NOT be dropped on
the peek failure (fail-open).

#### Scenario: A flow to a blocked domain on a shared IP is dropped by SNI
- **WHEN** a redirected TLS flow's ClientHello carries an SNI the policy blocks, even though its destination IP is not itself blocked
- **THEN** the flow is dropped

#### Scenario: An allowed flow's handshake is replayed intact
- **WHEN** a redirected flow is allowed after peeking its ClientHello
- **THEN** the peeked bytes are delivered to the destination first and the flow proceeds byte-for-byte transparently

#### Scenario: A non-TLS or SNI-less flow falls back and is not dropped
- **WHEN** a redirected flow carries no recoverable SNI (not TLS, truncated, or no server_name)
- **THEN** the flow is decided on its destination IP and is not dropped because the peek found no SNI
