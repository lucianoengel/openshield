-- SOAR-2b: a recurring incident is LINKED to the one it recurs from.
--
-- The lifecycle is forward-only on purpose (030): MTTA and MTTR are derived from its timestamps, and a
-- state machine that can move backwards makes "acknowledged at" meaningless. So "reopen" is not a
-- transition here and will not become one. But refusing the transition left a real hole: when the same
-- burst returns after an incident was closed, a NEW incident row appears with a new id and NOTHING
-- connects it to its predecessor.
--
-- THAT IS THE ACTUAL HARM. An operator looking at incident 431 cannot tell whether this subject is new
-- trouble or the fourth time this month that someone closed the same thing — and those are opposite
-- conclusions. The recurrence is precisely the signal that the previous close was premature, and it was
-- the one signal the model discarded.
--
-- recurrence_of points at the immediately preceding incident of the same kind for the same subject or
-- entity; recurrence_count is how many times this has now come back (0 = first occurrence). The link is
-- established at INSERT time by the materializer, never retroactively — a chain built later would be a
-- correlation nobody ran.
--
-- Additive: existing rows keep recurrence_of NULL and recurrence_count 0, which is exactly what they
-- are (unlinked, and never observed to recur). No backfill: inferring a chain across historic rows
-- would be inventing a judgement the product never made about them.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recurrence_of    BIGINT REFERENCES incidents(id);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recurrence_count INTEGER NOT NULL DEFAULT 0;

-- The predecessor lookup is "most recent non-open incident of this kind for this subject", run once per
-- newly inserted incident. Without an index it is a sequential scan of every incident ever raised, on
-- the correlation loop's hot path.
CREATE INDEX IF NOT EXISTS incidents_recur_subject_idx ON incidents (kind, subject_id, id DESC);
CREATE INDEX IF NOT EXISTS incidents_recur_entity_idx  ON incidents (kind, entity_id, id DESC)
    WHERE entity_id IS NOT NULL;

-- Walking a chain backwards is the read this exists to serve.
CREATE INDEX IF NOT EXISTS incidents_recurrence_of_idx ON incidents (recurrence_of)
    WHERE recurrence_of IS NOT NULL;
