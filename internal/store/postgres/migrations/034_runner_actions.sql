-- SOAR-8: the record linking an intent id to the external API call it caused.
--
-- This is the first table for actions taken OUTSIDE OpenShield. D253/D254 enact intents inside the
-- platform and both are restored when the intent's TTL lapses; disabling a user or revoking their
-- sessions in an identity provider is IRREVERSIBLE, and expiry restores nothing. An irreversible action
-- with no record of what triggered it cannot be explained to the person it was applied to.
CREATE TABLE IF NOT EXISTS runner_actions (
    id          BIGSERIAL PRIMARY KEY,
    connector   TEXT NOT NULL,
    intent_id   TEXT NOT NULL,
    verb        TEXT NOT NULL,
    subject     TEXT NOT NULL,   -- the PSEUDONYM (D23), passed through unresolved
    action      TEXT NOT NULL,   -- disable-user | revoke-sessions (runner.Action)
    target      TEXT NOT NULL DEFAULT '',  -- the URL that was called
    -- claimed | executed | failed. The claim is taken BEFORE the call so this is at-most-once rather than
    -- at-least-once: for "disable this account", a duplicate on redelivery is the failure that gets a SOAR
    -- turned off. The cost is that a crash between claim and call leaves an action never performed — and a
    -- row stuck in `claimed` is exactly the visible artifact an operator needs to notice that.
    state       TEXT NOT NULL DEFAULT 'claimed',
    http_status INTEGER NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT '',
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- AT MOST ONCE PER (connector, intent). A redelivered or replayed intent must not re-disable an account.
-- The unique index is the mechanism, not a backstop: the claim is an ON CONFLICT DO NOTHING insert, so
-- whichever caller claims first is the only one that calls.
CREATE UNIQUE INDEX IF NOT EXISTS runner_actions_once_idx ON runner_actions (connector, intent_id);

-- "What did we do to this subject, and what authorized it?"
CREATE INDEX IF NOT EXISTS runner_actions_subject_idx ON runner_actions (subject, at DESC);
CREATE INDEX IF NOT EXISTS runner_actions_intent_idx ON runner_actions (intent_id);
