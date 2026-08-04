-- CONSOLE-1: split the admin tier's two authorities apart.
--
-- `admin` meant "can change configuration" AND "can read everything held about a named human" — release
-- a legal hold, compile the DSAR dossier, read the record of who looked at what. Those are two jobs, and
-- every privacy regime this project claims to help with expects the person answering for the second to
-- be independent of the first.
--
-- The privacy authority is a SECOND COLUMN rather than a fourth tier, because it is not more access than
-- admin or less: it is other access. Ranked above admin it would inherit configuration; below, an admin
-- would inherit the dossier. Neither is the separation being asked for.
ALTER TABLE operator_roles ADD COLUMN IF NOT EXISTS privacy_officer BOOLEAN NOT NULL DEFAULT false;

-- EXISTING ADMINS KEEP BOTH, AND THE UPGRADE SAYS SO.
--
-- Unlike the principal renamespacing in 048, this is not a guess. `admin` DID mean both authorities up to
-- this migration, so carrying that forward preserves exactly what each administrator already had — no
-- access is created and none is silently taken away in an upgrade nobody read the notes for. The legacy
-- `operator` role, which ranks as admin, is treated the same way for the same reason.
--
-- WHAT THAT MEANS, PLAINLY: an upgraded deployment has the separation available and not yet in force.
-- Nothing is separated until an administrator decides who the privacy officer is. The notice below is
-- how they find out there is a decision to make.
--
-- Taking it back is one command: `openshield-server operator-role set <identity> admin` replaces the
-- whole grant, dropping the privacy authority. Granting it is
-- `operator-role set <identity> privacy-officer` — a privacy officer with no tier reaches the three
-- data-subject routes and nothing else, which is the point.
--
-- This runs once (schema_migrations records it), so a later revocation is not re-granted by a re-run.
DO $$
DECLARE fused_count INT;
BEGIN
    UPDATE operator_roles SET privacy_officer = true
     WHERE role IN ('admin', 'operator') AND NOT revoked AND NOT privacy_officer;
    GET DIAGNOSTICS fused_count = ROW_COUNT;
    IF fused_count > 0 THEN
        RAISE NOTICE 'CONSOLE-1: % operator(s) held the admin tier, which until now also granted DSAR '
            'export, legal-hold release and the view audit. They keep both so this upgrade takes no '
            'access away, and are now listed as `admin,privacy-officer`. THE SEPARATION IS AVAILABLE '
            'BUT NOT IN FORCE: decide who the privacy officer is, grant them with '
            '`openshield-server operator-role set <identity> privacy-officer`, and narrow each '
            'administrator with `openshield-server operator-role set <identity> admin`.', fused_count;
    END IF;
END $$;
