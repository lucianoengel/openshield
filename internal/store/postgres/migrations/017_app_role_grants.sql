-- Complete the non-owner application role (PLAT-6b, closing SEC-6).
--
-- Migration 013 created openshield_writer with LEDGER grants only (audit_entries/key_epochs/
-- anchors) — enough for the ledger-writing binaries, but the control-plane server also writes the
-- AGGREGATE tables (telemetry, alerts, cases, identities, …). Until every binary can run as a
-- non-owner role, they all connect as the OWNER, and migration 010's append-only trigger stays
-- owner-bypassable in the running product (SEC-6's actual condition). This makes openshield_writer
-- the COMPLETE non-owner application privilege set: the ledger stays append-only-constrained (its
-- 010 trigger + no DELETE grant), and the aggregate tables get full DML.
--
-- The role is still NON-OWNER: it cannot ALTER a table or disable the append-only trigger (that
-- needs ownership), and — unlike SET ROLE from the owner — a LOGIN member of it cannot RESET back
-- to the owner. That is the property that makes the DB-level append-only boundary real.

GRANT SELECT, INSERT, UPDATE, DELETE ON
    agent_identities, enrollment_tokens, fleet_telemetry, peer_alerts,
    investigation_views, cases, case_notes, legal_holds, peerueba_version
    TO openshield_writer;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO openshield_writer;

-- Future tables (added by later migrations, created by the owner) auto-grant to the app role, so
-- a new table does not silently break a non-owner app until someone remembers to grant it.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openshield_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO openshield_writer;
