-- Persisted peer-UEBA context-version base (SEC-10).
--
-- The analyzer's context_version counter is in-memory and resets to 0 on restart, so a
-- version string ("ctx-N") from one run collides with the same N from another run — two
-- different populations sharing a context_version, which breaks D27's attribution of WHICH
-- context a Decision saw. The control plane reserves a monotonic BLOCK of version space per
-- startup from this single-row counter, so each run's versions sit in a distinct, higher
-- range than any prior run (the ledger-sequence reservation pattern, D66).

CREATE TABLE IF NOT EXISTS peerueba_version (
    id      INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- exactly one row
    next_base BIGINT NOT NULL DEFAULT 0
);
INSERT INTO peerueba_version (id, next_base) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
