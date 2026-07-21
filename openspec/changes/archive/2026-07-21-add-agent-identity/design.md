## Context

The control plane (T-023) stores telemetry tagged with a self-asserted agent_id (D41). No identity,
no enrollment, no signature verification. The audit ledger already establishes the pattern that
sequence numbers make suppression detectable. Ed25519 is already used for the ledger's forward-
secure keys and anchors, so the crypto is familiar.

## Goals / Non-Goals

**Goals:**
- Per-agent Ed25519 identity; private key never leaves the host; never a shared secret.
- Single-use, short-TTL enrollment binding a public key to an agent id.
- Signed telemetry with a monotonic sequence; the control plane verifies signature AND detects
  sequence gaps (suppression).
- Per-agent revocation.

**Non-Goals:**
- mTLS transport auth (complementary, TLS-config); key rotation/re-enrollment; token-issuance
  authorisation policy (operator concern).

## Decisions

### Agent identity: `internal/agent/identity`
`Identity{ AgentID string; priv ed25519.PrivateKey; pub ed25519.PublicKey }`. `Generate(agentID)`
makes a keypair. `Sign(seq, payload) []byte` signs the canonical envelope. The private key is
in-process only; persistence to disk (encrypted at rest) is a deployment concern, noted.

### Enrollment: single-use, short-TTL token, stored hashed
Control plane `IssueToken(ttl)` returns a random token to the admin and stores only its SHA-256
hash with an expiry — a leaked database does not leak usable tokens. `Enroll(token, agentID, pub)`:
hash the presented token, look it up, reject if missing/expired/used, then insert the identity
(agent_id → pub, enrolled_at) and mark the token used in ONE transaction. Single-use is enforced
by the transaction: a second enroll with the same token finds it used.

A token is enrollment-only, not a signing key: a stolen token enrolls a bogus (revocable, visible)
agent but cannot impersonate an existing one, whose signatures require its private key.

### Signed telemetry + sequence-gap detection
Canonical envelope: length-prefixed `("openshield.tel.v1", agent_id, sequence, payload)`, same
discipline as the ledger's canonical bytes. Control plane `VerifySigned(agentID, seq, payload,
sig)`:
1. Load the identity; reject if unknown or REVOKED.
2. Verify the Ed25519 signature against the enrolled key.
3. Check the sequence: `seq == last_seq + 1` is in-order; `seq > last_seq + 1` is a GAP (messages
   suppressed) — recorded as a gap event, the telemetry still accepted (the message is authentic,
   the gap is the signal); `seq <= last_seq` is a replay/reorder — rejected.
4. Advance last_seq.

The gap is the evidentiary property: an attacker who drops messages between agent and control plane
cannot hide it, because the next accepted message's sequence reveals the hole — exactly the audit
log's reasoning.

### Revocation
`Revoke(agentID)` sets `revoked_at`. `VerifySigned` rejects a revoked identity. Per-agent, so
containing one endpoint does not touch the fleet.

### Storage
Migration `006`: `agent_identities(agent_id PK, public_key BYTEA, enrolled_at, revoked_at NULL,
last_sequence BIGINT DEFAULT 0)` and `enrollment_tokens(token_hash PK, expires_at, used_at NULL)`.

## Risks / Trade-offs

- **Root on the host reads the private key** (D16). Attributable-and-revocable is the honest bound,
  not unforgeable. Stated on every surface.
- **A gap is ambiguous** (lossy network vs suppression). Reported as a gap for investigation, not an
  accusation — like the dead-man's-switch (D42). The offline queue (T-024) means benign gaps are
  rare because a reconnecting agent delivers its backlog in order.
- **In-memory private key.** Disk persistence (encrypted) for restart survival is deployment; noted,
  and it is the same T-017-adjacent gap the ledger's write-resume flagged.
- **mTLS not built.** Application-layer identity is the evidentiary half; connection auth is
  complementary and deferred, stated so it is not mistaken for absent security.
