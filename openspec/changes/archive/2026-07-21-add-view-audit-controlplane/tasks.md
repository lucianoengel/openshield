## 1. View recording

- [x] 1.1 Migration `007`: `investigation_views(id, viewer, subject_filter, event_id, viewed_at)`
- [x] 1.2 `Server.RecordView(ctx, viewer, filter)` — reject empty viewer; insert
- [x] 1.3 `Server.View(ctx, viewer, eventID)` — record the view AND return the event's telemetry, in
      one call

## 2. Read-back

- [x] 2.1 `Server.Views(ctx, eventID)` / `Server.ViewsBy(ctx, viewer)`

## 3. Tests (real Postgres)

- [x] 3.1 **Test**: View records a labelled view and returns telemetry; Views reads it back.
      `TestViewRecordsAndServes`
- [x] 3.2 **Test**: an empty viewer is rejected. `TestEmptyViewerRejected`
- [x] 3.3 **Test**: the recorded viewer carries the unauthenticated label. `TestViewerLabelled`

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): control-plane view accountability; viewer
      labelled unauthenticated; non-evidentiary; operator authn a sibling gap
- [x] 4.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| View serves without recording (RecordView no-op) | `TestViewRecordsAndServes`, `TestViewerLabelled` |
| empty viewer accepted | `TestEmptyViewerRejected` |

`View` records a labelled view and returns the telemetry in one call; `Views`/
`ViewsBy` read it back. An empty viewer is rejected (nothing recorded), and the
recorded viewer carries the `unauthenticated:` label. All against real Postgres;
guards mutation-tested. The view log is documented non-evidentiary with a
self-asserted viewer; operator authentication is named as a sibling unbuilt gap.
Docs: D47.
