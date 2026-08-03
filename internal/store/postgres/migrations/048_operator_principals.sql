-- CONSOLE-1: one canonical operator principal, and four-eyes that compares the PERSON.
--
-- Two credential paths minted identity strings that never agreed. For the AUDIT trail a certificate
-- produced `operator:<CN>` and a token produced the raw `sub`; for the ROLE lookup the same certificate
-- produced the bare `<CN>`. Threading the token identity through unchanged would have let one human
-- request an approval from the CLI as `operator:alice` and grant it from the browser as `alice`: two
-- different strings, `requester <> approver` satisfied, and two-person control gone on case closure,
-- CONTAIN and fleet ENFORCEMENT_DISABLE.
--
-- Worse, since SEC-D the approval row would have recorded that collapse as `strong` assurance, because
-- the deployment genuinely could not tell the two credentials apart.

-- 1. EXISTING GRANTS ARE LEFT DENYING, AND SAY SO.
--
-- There is nothing to renamespace. Role grants were stored under a BARE identity — `certIdentity`
-- returned the CommonName unprefixed for the role lookup, while `operatorIdentity` returned
-- `operator:<CN>` for the audit trail, so one person had two strings in one process for two purposes.
-- SCIM stored the bare `userName` in the same column.
--
-- THAT SHARED COLUMN IS THE COLLISION. A certificate CommonName and an identity-provider subject were
-- indistinguishable once stored, so an IdP that called someone `alice` inherited whatever was granted to
-- the certificate whose CommonName is alice — and nothing anywhere recorded which one a row was for.
--
-- A bare row therefore cannot be renamespaced, because the information needed to do it correctly was
-- never captured. Guessing `cert:` would grant certificate access to rows meant for SSO subjects, and
-- guessing an issuer would grant SSO access to rows meant for certificates. Both are silent, and both
-- fail open.
--
-- So every legacy row is LEFT ALONE, which leaves it denying: no principal resolves to an unnamespaced
-- string any more. The rows stay visible to `operator-role list` so an administrator can see exactly
-- what to re-grant, rather than being deleted and forgotten. RE-GRANTING EVERY OPERATOR IS REQUIRED ON
-- UPGRADE, and the notice below says how many.
--
-- That is a real operational cost and it is the only safe option: re-granting is one command per
-- operator, and a wrongly-guessed grant is an incident nobody would detect.
DO $$
DECLARE legacy_count INT;
BEGIN
    SELECT count(*) INTO legacy_count FROM operator_roles
     WHERE identity NOT LIKE 'cert:%' AND identity NOT LIKE 'oidc:%' AND identity NOT LIKE 'svc:%';
    IF legacy_count > 0 THEN
        RAISE NOTICE 'CONSOLE-1: % operator role grant(s) use the pre-namespace identity format and now '
            'GRANT NOTHING. They are kept so you can see what to restore. Re-grant each with '
            '`openshield-server operator-role set cert:<CommonName>|oidc:<issuer>#<subject> <role>`. '
            'They were not migrated automatically because a bare identity does not record whether it '
            'was a certificate CommonName or an identity-provider subject, and guessing either way '
            'grants access to the wrong credential.', legacy_count;
    END IF;
END $$;

-- 2. ACCOUNTS: which principals are the same PERSON.
--
-- Four-eyes must compare people, and a person may hold a certificate and an SSO identity. Without this,
-- the control compares credentials, and anyone holding two satisfies it alone.
CREATE TABLE IF NOT EXISTS operator_identities (
    -- The canonical principal: `cert:<cn>`, `oidc:<issuer>#<sub>`, `svc:<name>`.
    principal  TEXT PRIMARY KEY,
    -- The person. Free-form and administrator-chosen (an employee id, an email) so an existing directory
    -- can be mirrored without this table inventing its own namespace.
    account_id TEXT NOT NULL,
    linked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    linked_by  TEXT NOT NULL DEFAULT ''
);
-- Finding every credential of one person is the question an investigation asks.
CREATE INDEX IF NOT EXISTS operator_identities_account_idx ON operator_identities (account_id);

-- 3. APPROVALS COMPARE THE ACCOUNT, AND STILL RECORD THE CREDENTIAL.
--
-- Both, not either. The ACCOUNT is what the control compares — that is the fix. The PRINCIPAL is what
-- the audit trail shows, because "alice approved it" is not the same fact as "alice approved it from
-- the browser session she opened on an unmanaged laptop", and an investigation needs the second.
--
-- Defaulted to the principal itself for existing rows: an operator with one credential IS their own
-- account, so historical approvals keep exactly the meaning they had. Nothing is retroactively claimed.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS requester_account TEXT NOT NULL DEFAULT '';
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approver_account  TEXT NOT NULL DEFAULT '';
UPDATE approvals SET requester_account = requester WHERE requester_account = '';
UPDATE approvals SET approver_account = approver
 WHERE approver_account = '' AND approver IS NOT NULL AND approver <> '';
