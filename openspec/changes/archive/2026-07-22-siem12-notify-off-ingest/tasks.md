# Tasks — SIEM-12 notify off ingest
- [x] Notification.ID idempotency key (json), stamped at emit, stable across the delivery retry.
- [x] emit queues to a bounded channel (non-blocking; drop+count NotifyDropped when full).
- [x] SetNotifier starts a single async delivery worker (deliverLoop) once.
- [x] NotifyDropped counter exposed as a Prometheus metric.
- [x] Overdue test: assert count synchronously, poll for async delivery; assert id present.
- [x] In-package test: emit returns promptly on a blocking sink; worker gets an id-stamped notification.
- [x] Mutation: revert emit to synchronous Notify -> the block test times out.
- [x] make all clean; docs D159; sync; archive; commit; push; memory.
