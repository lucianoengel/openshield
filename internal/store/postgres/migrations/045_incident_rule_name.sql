-- Named correlation rules on cross-domain incidents (XDR-4c).
--
-- XDR-4's ordered-sequence rule was reachable from exactly one place: the GET /incidents query
-- parser. The scheduled correlation loop — the mechanism that actually raises incidents and pages
-- humans — never set Sequence, so a narrative rule could be ASKED but never TOLD. Making the loop run
-- named hunts means several cross-domain rules can match one entity on one tick, and that is what
-- this column exists for.
--
-- THE INDEX RESHAPE IS MANDATORY, NOT COSMETIC — migration 028 wrote this argument one level up when
-- it put the cross-domain rule alongside the burst rule:
--
--   "Left as-is, a burst incident and a cross-domain incident for the same asset would collide and
--    the second upsert would silently overwrite the first — an operator would lose an incident with
--    no trace."
--
-- Two HUNTS are that situation one level down. They share kind='cross_domain', so both existing
-- conflict targets treat them as the same incident, and what that produces is worse than a lost row
-- because it looks like it is working: the second hunt takes DO UPDATE, overwrites the first's alert
-- count / domain count / domain list with its own narrower numbers, and — because only a genuine
-- INSERT pages (SOAR-1/D220, via RETURNING xmax = 0) — NEVER PAGES AT ALL. A second attack narrative
-- on the same asset is folded silently into the first one's incident, and every subsequent tick the
-- row flip-flops between whichever hunts still match.
--
-- '' is the UNNAMED breadth rule. No backfill is needed and none would be honest: every existing row
-- was raised by the breadth rule, which is precisely what '' means.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS rule_name TEXT NOT NULL DEFAULT '';

DROP INDEX IF EXISTS incidents_open_entity_idx;
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_entity_rule_idx
    ON incidents (entity_id, rule_name) WHERE state = 'open' AND kind = 'cross_domain';

-- The kind+subject index needs the same treatment: a cross-domain incident carries a representative
-- subject_id for display, so two hunts on one asset collide here too. The burst rule is unaffected —
-- its rows all carry rule_name '' and there is only ever one burst rule.
DROP INDEX IF EXISTS incidents_open_kind_subject_idx;
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_kind_rule_subject_idx
    ON incidents (kind, rule_name, subject_id) WHERE state = 'open';
