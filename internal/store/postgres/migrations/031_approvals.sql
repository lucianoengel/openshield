-- SOAR-3: a reusable four-eyes approval object.
--
-- Four-eyes existed exactly once, welded to case closure (D36, migration 011). The predicate was right —
-- requester≠approver enforced inside the UPDATE, so a race cannot produce two approvals — but it was
-- reachable from nothing else. SOAR-4 (wait-for-approval steps), SOAR-7 (high-impact response intents) and
-- SOAR-8 (IdP responder, "four-eyes always") each need the same control over a different subject, and
-- re-implementing it per feature is how one of them ends up subtly wrong — the one that lets a single
-- operator contain a fleet.
--
-- (subject_kind, subject_id) rather than a foreign key per consumer: a response-intent id and a
-- playbook-step id do not live in one table, and a nullable FK column per consumer is exactly how the
-- cases version got welded in.
CREATE TABLE IF NOT EXISTS approvals (
    id           BIGSERIAL PRIMARY KEY,
    subject_kind TEXT NOT NULL,              -- case-close | playbook-step | response-intent
    subject_id   TEXT NOT NULL,              -- opaque to this table; meaningful to the consumer
    state        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired
    requester    TEXT NOT NULL,              -- operator:<CN> who asked
    approver     TEXT,                       -- operator:<CN> who resolved it; MUST differ from requester
    reason       TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    -- Expiry is enforced in the UPDATE predicate (expires_at > now()), NOT by a sweeper: an expired request
    -- is unapprovable the instant it expires, with no background job to fall behind. A request left open
    -- for a week is not consent.
    expires_at   TIMESTAMPTZ NOT NULL
);

-- A consumer looks up the decision for its subject.
CREATE INDEX IF NOT EXISTS approvals_subject_idx ON approvals (subject_kind, subject_id);

-- At most one PENDING approval per subject: two live requests for the same action would let a requester
-- shop for an approver.
CREATE UNIQUE INDEX IF NOT EXISTS approvals_pending_subject_idx
    ON approvals (subject_kind, subject_id) WHERE state = 'pending';
