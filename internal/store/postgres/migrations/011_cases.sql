-- Case / investigation workflow (Phase F3).
--
-- A case tracks an operator investigation of a pseudonymous subject. Closing a case is a
-- FOUR-EYES action (D36): one operator requests closure, a DIFFERENT operator approves it,
-- so no single operator can unilaterally close (and thereby bury) an investigation. The
-- requester and approver are recorded from their VERIFIED client certificates (D56).

CREATE TABLE IF NOT EXISTS cases (
    id                  BIGSERIAL PRIMARY KEY,
    subject_id          TEXT NOT NULL,          -- the pseudonymous subject under investigation (D23)
    status              TEXT NOT NULL DEFAULT 'open', -- open | close_requested | closed
    opened_by           TEXT NOT NULL,          -- operator:<CN>
    assigned_to         TEXT,                   -- operator:<CN>, or null
    close_requested_by  TEXT,                   -- operator who requested closure (four-eyes, D36)
    closed_by           TEXT,                   -- operator who approved closure (MUST differ)
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS cases_subject_idx ON cases (subject_id);
CREATE INDEX IF NOT EXISTS cases_status_idx ON cases (status);

CREATE TABLE IF NOT EXISTS case_notes (
    id         BIGSERIAL PRIMARY KEY,
    case_id    BIGINT NOT NULL REFERENCES cases(id),
    author     TEXT NOT NULL,                   -- operator:<CN>
    note       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS case_notes_case_idx ON case_notes (case_id);
