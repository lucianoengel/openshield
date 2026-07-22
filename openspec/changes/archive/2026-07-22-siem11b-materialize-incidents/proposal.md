# SIEM-11b: materialize incidents (id + state, acknowledgeable as a unit)

## Why

Correlation computed incidents ON READ — a query over `peer_alerts` per GET — so incidents had no
identity and no state. The SIEM-6 acknowledgement could therefore only attach to individual alerts,
and a case (D107) could not target an incident as a UNIT. An operator could not say "I've triaged
THIS incident."

## What Changes

- **An `incidents` table** (migration 018) persists a correlated incident with a stable id and a
  lifecycle state (`open` / `acknowledged`). A partial unique index enforces at most ONE OPEN
  incident per subject.
- **`MaterializeIncidents`** runs the correlation and UPSERTs each subject's open incident: a
  re-correlated burst extends the open incident (refreshes counts, widens the span) rather than
  duplicating it; an acknowledged incident is left untouched, so a later burst opens a fresh one
  only after the current is triaged.
- **`AcknowledgeIncident`** acknowledges an incident as a unit — first-ack-wins, phantom id →
  `ErrIncidentNotFound`, a DB failure propagates (not "not found", SEC-11). Exposed as
  `POST /incidents/ack?id=N`, operator taken from the verified client cert.
- **`GET /incidents` now materializes then returns the STORED incidents** (with id + state), so the
  list is acknowledgeable/case-linkable rather than a recomputed-every-GET view.

This modifies the `control-plane` capability. No core change.

## Impact

- Affected specs: `control-plane`
- Affected code: migration `018_incidents.sql`, `internal/controlplane/incidents.go` (new),
  `correlate.go` (handler), `operator_read.go` + `enroll_http.go` (mount ack), migration-count test.
- Not in scope (stated): a full incident lifecycle beyond open/acknowledged (closed/assigned live as
  cases, D107); case-linking an incident by its id (OpenCaseForIncident still takes the computed
  Incident value — a follow-up); a background materialization timer (materialize-on-read is used;
  a timer is an alternative deployment refinement); a multi-rule correlation engine.
