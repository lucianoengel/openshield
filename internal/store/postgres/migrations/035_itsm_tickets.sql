-- SOAR-8 increment 2: incident ⇄ ticket linkage.
--
-- DELIBERATELY NOT `runner_actions` (034), and the reason is the whole design decision. That table records
-- IRREVERSIBLE, at-most-once, never-retried acts: the claim is taken before the call precisely so a
-- redelivery cannot repeat it. A ticket is the reverse — MUTABLE, RETRYABLE and synced in BOTH directions,
-- with its row updated on every poll. Sharing one table would force one set of semantics onto the other,
-- and the dangerous direction is obvious: relaxing runner_actions to allow updates and retries, to
-- accommodate tickets, would weaken the guarantee protecting the irreversible half.
CREATE TABLE IF NOT EXISTS itsm_tickets (
    id             BIGSERIAL PRIMARY KEY,
    connector      TEXT NOT NULL,
    incident_id    BIGINT NOT NULL,
    ticket_ref     TEXT NOT NULL,              -- the remote system's identifier
    ticket_url     TEXT NOT NULL DEFAULT '',
    -- The last status OBSERVED, including one this connector does not recognise. Recording it is what
    -- lets an operator see that a remote vocabulary changed, instead of wondering why nothing closes.
    last_status    TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at TIMESTAMPTZ
);

-- One ticket per (connector, incident). Repeated sync runs must not open a second.
CREATE UNIQUE INDEX IF NOT EXISTS itsm_tickets_once_idx ON itsm_tickets (connector, incident_id);
CREATE INDEX IF NOT EXISTS itsm_tickets_ref_idx ON itsm_tickets (connector, ticket_ref);
