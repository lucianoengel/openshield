# Tasks — SIEM-1 event search

- [x] `EventFilter` + `EventRow` (metadata, no payload).
- [x] `SearchTelemetry` — parameterized WHERE, verified-only, time window, hard cap, newest-first.
- [x] `parseEventFilter` — SEC-8 fail-loud parse + cap.
- [x] Mount `/events` on `OperatorReadHandler`, operator-gated, 400 on bad filter.
- [x] Test: agent / kind / event-id / time-window / verified-only filters + newest-first.
- [x] Mutation: verified filter disabled → verified-only leaks the self-asserted row (fails).
- [x] Mutation: parse cap removed → 1,000,000 ask not clamped (fails).
- [x] `make all` clean.
- [x] docs/decisions.md D132; sync spec; archive; commit; push; memory.
