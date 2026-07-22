-- Non-owner ledger writer role (SEC-6, completing D63).
--
-- Migration 010's append-only trigger is honest-bounded: a table OWNER can DISABLE it, so
-- DB-level append-only was only advisory against a leaked OWNER credential. The complete fix
-- (named in 010's own comment) is to run the application under a NON-OWNER restricted role
-- that can INSERT and perform the permitted tombstone UPDATE but CANNOT ALTER the table or
-- disable the trigger. This creates that role and grants exactly those rights.
--
-- Deploy: the app connects as the owner for MIGRATIONS, then runs under this role for normal
-- operation (OPENSHIELD_DB_WRITER_ROLE=openshield_writer → the ledger pool SET ROLEs to it).
-- The owner role is reserved for migrations. A leaked writer credential can append and
-- tombstone (both already chain-visible / Verify-checkable) but cannot rewrite history or
-- turn the guard off.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openshield_writer') THEN
        CREATE ROLE openshield_writer NOLOGIN;
    END IF;
END
$$;

-- The app tables the ledger writes. The writer gets SELECT/INSERT/UPDATE — the append-only
-- trigger constrains WHICH updates (only the tombstone), and DELETE is deliberately NOT
-- granted (belt-and-suspenders with the trigger's DELETE ban).
GRANT SELECT, INSERT, UPDATE ON audit_entries TO openshield_writer;
GRANT SELECT, INSERT, UPDATE ON key_epochs TO openshield_writer;
GRANT SELECT, INSERT, UPDATE ON anchors TO openshield_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO openshield_writer;
-- The app reads schema_migrations to decide it does NOT need to migrate (SEC-6 skip check).
GRANT SELECT ON schema_migrations TO openshield_writer;

-- Allow the migrating user to SET ROLE to the writer (membership), so a superuser is not
-- required at runtime — the app connects as the owner and drops to the writer role.
GRANT openshield_writer TO CURRENT_USER;
