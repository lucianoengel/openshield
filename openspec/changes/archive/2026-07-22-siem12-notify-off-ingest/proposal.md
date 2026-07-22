# SIEM-12: move notification delivery off the ingest path + idempotency

## Why

Notification delivery was SYNCHRONOUS inside telemetry ingest: `handleSigned → observePeer → emit`
called `notifier.Notify` inline, and with the SIEM-8 bounded retry a slow/failing webhook could stall
the ingest handler for the whole backoff window (worst case seconds) per alert — backpressure from a
broken sink onto the detection pipeline. And a client that times out AFTER the server already
delivered would retry with no idempotency key, double-paging the receiver.

## What Changes

- **Async delivery, off the ingest path**: `emit` now QUEUES the notification to a bounded channel
  and returns immediately; a single delivery worker (started once by `SetNotifier`) drains the queue
  and calls `Notify`. A slow webhook can no longer stall ingest. If the queue is full (a delivery
  backlog), the notification is dropped and counted (`NotifyDropped`, exposed as a metric) — losing a
  page degrades responsiveness, never the record, and never blocks ingest.
- **Idempotency key**: each `Notification` carries a stable `ID` (stamped at emit), included in the
  webhook body, so a receiver dedupes a retried delivery — a client-timeout-after-success retry no
  longer double-pages.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/notify/notify.go` (Notification.ID), `internal/controlplane/notify.go`
  (async emit + worker + id), `controlplane.go` (queue field), `metrics.go` (NotifyDropped counter).
- Not in scope (stated): a durable/persistent notification queue that survives restart (the queue is
  in-memory best-effort, consistent with delivery being additive to the recorded alert, D30);
  multiple sinks / fan-out (SIEM-8 follow-up); receiver-side dedup implementation (the id is provided;
  dedup is the receiver's job).
