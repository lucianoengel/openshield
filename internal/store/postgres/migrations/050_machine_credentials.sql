-- CONSOLE-1: give the machine principal a credential it can actually present.
--
-- `svc:<name>` has parsed, been grantable and been refused four-eyes since D468/D469, and nothing could
-- ever present one: authentication mints `cert:` from a certificate and `oidc:` from a token, and there
-- was no third path. Every `svc:` grant authorized a caller that could not exist.
--
-- The gap is what puts an automation on a HUMAN's credential — the only ones that work — and that is the
-- precise input the four-eyes account comparison exists to reject.
CREATE TABLE IF NOT EXISTS machine_credentials (
    -- The canonical principal, `svc:<name>`. One credential per machine identity: two live secrets for
    -- one identity is the state rotation exists to end.
    principal     TEXT PRIMARY KEY,
    -- The SHA-256 of the token, hex. NEVER the token. Issuance is the only moment the plaintext exists,
    -- so a leaked database yields no working credential — the same rule as the enrolment tokens (D44).
    secret_sha256 TEXT NOT NULL,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NOT NULL, with no default and no sentinel for "never". There is no non-expiring machine credential
    -- in this system; the application caps the life at 90 days as well.
    expires_at    TIMESTAMPTZ NOT NULL,
    issued_by     TEXT NOT NULL DEFAULT '',
    revoked       BOOLEAN NOT NULL DEFAULT false,
    -- Null until it authenticates something. A credential that has never been used is either not
    -- deployed or not needed, and an access review should see which.
    last_used_at  TIMESTAMPTZ,
    rotations     INT NOT NULL DEFAULT 0
);

-- Authentication looks the secret up by its hash, so this index is the hot path — and it is UNIQUE
-- because two principals sharing a secret would make "who is calling" ambiguous at the one moment it
-- must not be.
CREATE UNIQUE INDEX IF NOT EXISTS machine_credentials_secret_idx ON machine_credentials (secret_sha256);
-- Finding what is about to stop working is the question an operator asks before a holiday.
CREATE INDEX IF NOT EXISTS machine_credentials_expiry_idx ON machine_credentials (expires_at)
    WHERE NOT revoked;
