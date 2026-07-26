-- SOAR-2: the incident lifecycle gains attribution for its transitions.
--
-- An incident was `open` or `acknowledged` with no way to record that it was triaged, contained, or
-- closed — exactly the states SOAR's playbooks, approvals and MTTA/MTTR metrics need. The lifecycle is
-- forward-only (open → acknowledged → triaged → contained → closed): a state machine that can move
-- backwards makes time-to-acknowledge and time-to-resolve unmeasurable, which is the reason for recording
-- it at all. An incident that needs reopening becomes a NEW incident, which the partial-unique-on-open
-- indexes already permit once the old one leaves `open`.
--
-- Additive: existing rows keep their state, and no index changes (every new state is outside the
-- `state = 'open'` predicate, so advancing an incident frees its subject/entity exactly as `acknowledged`
-- already did).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS transitioned_by TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS transitioned_at TIMESTAMPTZ;
