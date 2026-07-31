-- SIEM-14: saved searches — a named hunt an analyst can re-run.
--
-- A SOC's hunts are institutional knowledge and they were living in people's shell history. The cost is
-- not typing: it is that the hunt which found something last quarter is not repeatable by the person on
-- shift tonight, and a detection that only one analyst can perform is not a detection the team has.
--
-- The stored form is THE QUERY STRING AN ANALYST TYPED, not a parsed structure. One representation
-- cannot drift from the other, running a saved search is re-parsing exactly what was saved, and a
-- parameter added to a search surface later is expressible in a saved search the same day without a
-- schema change here. It also means a saved search is validated by the surface's own parser at SAVE
-- time — see the note on refusal below.
--
-- surface names which read surface the query belongs to (alerts, events, logs). Without it the same
-- parameters mean different things: `?kind=` selects an event kind on /events and nothing on /search, so
-- a surface-less saved search would silently run somewhere it does not apply.
--
-- OWNERSHIP IS ATTRIBUTION, NOT ACCESS CONTROL. created_by/updated_by record who wrote the hunt so a
-- reviewer can ask them about it; the searches themselves are visible to every analyst, because a hunt
-- only one person can see is the problem this table exists to solve.
CREATE TABLE IF NOT EXISTS saved_searches (
    name        TEXT        PRIMARY KEY,
    surface     TEXT        NOT NULL,
    query       TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    created_by  TEXT        NOT NULL,
    updated_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS saved_searches_surface_idx ON saved_searches (surface, name);
