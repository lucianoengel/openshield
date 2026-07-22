# Design — materialize incidents

## One open incident per subject

An incident is a subject's current burst. Modeling it as "at most one OPEN incident per subject"
(a partial unique index on `subject_id WHERE state='open'`) gives a natural lifecycle: while a
subject is anomalous, its open incident is refreshed by each re-correlation (an idempotent upsert
that extends the span and updates the counts); acknowledging it moves it out of the open state, so
a later burst opens a NEW incident. This is why the ack targets the id and the upsert conflict is
scoped to the open state — an acknowledged incident is history, not overwritten.

## Materialize on read, live and identified

`GET /incidents` materializes the current correlation (idempotent upsert) then returns the stored
set, so the list is both live and carries stable ids/state within and across GETs — an operator can
acknowledge an incident and see it stay acknowledged on the next load. A background timer is an
alternative, but materialize-on-read needs no scheduler and keeps the endpoint self-contained.

## Acknowledgement honesty

Ack mirrors the alert ack (SIEM-6): first-ack-wins via the `state='open'` guard, a phantom id is
`ErrIncidentNotFound` via an existence probe, and a DB failure propagates rather than masquerading
as not-found (SEC-11). The test proves: one open incident survives re-materialization (no
duplicate), ack is first-wins, a new open incident opens after ack, a phantom errors, and an ack
against a closed pool is a real error. The mutation dropping the upsert's ON CONFLICT makes the
second materialization violate the unique index — the no-duplicate property fails.
