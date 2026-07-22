# Tasks — SIEM-11b materialize incidents
- [x] Migration 018: incidents table + partial unique index (one open per subject); count test 17->18.
- [x] MaterializeIncidents: correlate + upsert open-per-subject (extend span, refresh counts).
- [x] RecentIncidents reader; AcknowledgeIncident (first-wins, phantom->ErrIncidentNotFound, DB-error propagates).
- [x] POST /incidents/ack (operator cert); GET /incidents materializes then returns stored incidents.
- [x] Test: one open per subject on re-materialize; ack first-wins; new open after ack; phantom + closed-pool.
- [x] Mutation: drop the upsert ON CONFLICT -> the no-duplicate property fails.
- [x] incidents added to test DROP lists; make all clean; docs D155; sync; archive; commit; push; memory.
