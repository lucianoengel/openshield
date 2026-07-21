## Context

The control plane (T-023) persists telemetry and offers `Telemetry`/`TelemetryForEvent` read-backs.
No view is recorded when those are called. T-013's `Ledger.RecordView` exists on the agent ledger
but the CLI can't call it (no signer). The control plane is write-capable and serves fleet queries.

## Goals / Non-Goals

**Goals:**
- Record a view (viewer, query, time) when an investigation is served through the control plane.
- Serve-and-record as one operation; readable view log.
- Viewer labelled unauthenticated; honest non-evidentiary caveat.

**Non-Goals:**
- Operator authentication (distinct unbuilt piece); a network query API; recording local CLI reads
  of the agent's own ledger; making the view log tamper-evident.

## Decisions

### investigation_views table
Migration `007`: `investigation_views(id BIGSERIAL, viewer TEXT, subject_filter TEXT, event_id TEXT,
viewed_at TIMESTAMPTZ DEFAULT now())`. `subject_filter`/`event_id` capture WHAT was queried.

### View serves and records atomically
`Server.View(ctx, viewer, eventID)`: insert the view row AND return the telemetry for that event in
one call, so a caller cannot obtain the evidence without leaving a record. `viewer` must be
non-empty; callers pass `"unauthenticated:" + osUser`. A helper `Server.RecordView(ctx, viewer,
filter)` exists for a view that is not a single-event fetch (e.g. a subject sweep).

The insert precedes the read within the method, but both are in the same call; if the read fails the
view is still recorded (someone attempted to look), which is the conservative choice for an
accountability trail — an attempted view is more interesting than a failed one is uninteresting.

### Viewer labelling enforced
`View`/`RecordView` reject a viewer that does not carry an identity marker (empty), and the CLI/
callers prefix `unauthenticated:`. A test asserts a recorded view carries the label, so a future
caller cannot quietly record a bare, authoritative-looking name.

### Read-back
`Server.Views(ctx, eventID)` and `Server.ViewsBy(ctx, viewer)` return recorded views. Enough to
answer "who looked at this" — the D20 accountability.

## Risks / Trade-offs

- **Non-evidentiary, self-asserted viewer.** Stated on every surface; same caveat as the aggregate
  (D41). The alternative — no view trail — fails D20 outright. Loud-but-weak beats absent.
- **Recording an attempted-but-failed view.** Deliberate: an accountability trail should over-record
  rather than under-record access. Noted.
- **No operator authn yet.** The view captures the OS identity; authenticated operator identity is a
  sibling gap to T-017, flagged not solved.
- **Method-level, not a network API.** The seam is closed where queries are served; exposing it over
  the wire is a later interface decision, consistent with T-023's method-level read-backs.
