# Tasks — CONSOLE-8c

- [x] 1. `attachSpool` in `cmd/openshield-engine`: open the queue, `SetSpool`, loud eviction callback.
- [x] 2. A drain loop with its own interval, independent of the heartbeat ticker.
- [x] 3. Loud warning, naming the consequence, when no spool is configured.
- [x] 4. Declare `OPENSHIELD_QUEUE_DIR`/`_MAX`/`_FLUSH_INTERVAL` on `EngineFields`.
- [x] 5. Correct the false half of the `telemetry.go` claim rather than deleting it.
- [x] 6. Integration test: real engine, real broker outage, held then drained; plus the local-ledger
      assertion that keeps "lost view" and "lost evidence" distinguishable.
- [x] 7. Integration test: the no-spool warning names what is lost.
- [x] 8. Mutations: no spool attached; spool attached but never drained.
- [x] 9. Docs: D475 row, roadmap table updated.
