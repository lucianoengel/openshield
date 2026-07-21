-- Per-agent identity and enrollment (T-017).
--
-- Each agent has its OWN Ed25519 identity (never a shared secret). Enrollment
-- binds an agent's public key via a single-use, short-TTL token stored only as a
-- hash. Telemetry carries a monotonic sequence so suppression (a gap) is
-- detectable, and identity is revocable per agent.
CREATE TABLE IF NOT EXISTS agent_identities (
    agent_id      TEXT PRIMARY KEY,
    public_key    BYTEA NOT NULL,
    enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ,               -- NULL = active
    last_sequence BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash BYTEA PRIMARY KEY,            -- SHA-256 of the token; the token itself is never stored
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ                   -- NULL = unused; single-use
);
