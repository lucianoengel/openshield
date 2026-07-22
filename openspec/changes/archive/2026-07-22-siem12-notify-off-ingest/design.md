# Design — notify off the ingest path

## Queue + worker, never block ingest

The ingest handler must not wait on an external webhook. `emit` does a non-blocking send to a
buffered channel and returns; a worker goroutine (one, started once) delivers each notification with
the existing bounded retry. A backlog (worker slow because the sink is slow) fills the buffer, and a
full buffer drops-and-counts rather than blocking the sender — the same "no silent loss, never block
the pipeline" discipline the receive side uses. Delivery is best-effort and additive to the recorded
alert (D30), so dropping under sustained backpressure is the correct failure mode.

## Idempotency across the retry

The double-page risk is a client timeout after the server already delivered: the client retries the
same logical alert. A stable `ID` on the Notification, included in the JSON body, lets the receiver
dedupe. The id is stamped once at emit and is stable across the SIEM-8 delivery retry (which retries
the same Notification value), and distinct per logical alert (a new alert gets a new id).

## Proven

The async property is tested with a sink that blocks forever: `emit` returns promptly regardless, and
the worker picks the notification up (carrying a non-empty id). The mutation reverting emit to a
synchronous inline `Notify` makes emit block on the stuck sink — the test times out. The overdue test
now asserts the newly-overdue COUNT synchronously and polls for the async delivery.
