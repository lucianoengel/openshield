-- ZT-7: an operator's ROLE, held server-side instead of inside their certificate.
--
-- THE DEFECT THIS FIXES. The role was stamped into the client certificate's Subject OU at issuance
-- (PLAT-3/D58) and read from there on every request. So authorization was frozen for the certificate's
-- lifetime: demoting a responder to analyst, or removing someone's access entirely, did not take effect
-- until that certificate expired or the whole CA was rotated. There was no "revoke this operator's
-- responder rights now" primitive at all.
--
-- For a product whose thesis is that every security decision is explainable and auditable, an authorization
-- change that lands on a certificate-lifetime delay is a hole, not a missing integration — and it is the
-- kind an incident review finds the hard way, because the operator whose access "was removed" still had it.
--
-- THE CERTIFICATE STILL AUTHENTICATES. It says WHO (CommonName); this table says WHAT THEY MAY DO, NOW.
-- Splitting those is what makes a role change immediate, and it is the ordinary shape of every system that
-- got this right: identity is long-lived and slow to change, authorization is short-lived and must not be.
CREATE TABLE IF NOT EXISTS operator_roles (
    -- The certificate's CommonName. Not a surrogate key: the join to a presented certificate has to be on
    -- something the certificate actually carries, or the lookup needs a second mapping nobody maintains.
    identity   TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    -- REVOKED IS A ROW, NOT A DELETION. Deleting would fall back to the certificate's embedded role — i.e.
    -- removing someone's access would silently RESTORE whatever their certificate says, which is the
    -- opposite of the intent and exactly the sort of reversal nobody tests for.
    revoked    BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Who made the change. An authorization change is itself a security event, and one that cannot be
    -- attributed is not evidence.
    updated_by TEXT NOT NULL DEFAULT ''
);

-- "Who currently holds responder or above?" is the question asked during an incident, so it is indexed
-- rather than a scan.
CREATE INDEX IF NOT EXISTS operator_roles_role_idx ON operator_roles (role) WHERE NOT revoked;
