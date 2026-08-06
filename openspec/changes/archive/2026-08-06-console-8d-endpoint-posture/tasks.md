# Tasks — CONSOLE-8d

- [x] 1. `startPostureReporting` in `cmd/openshield-engine`: signed, on an interval, published once
      immediately so a starting endpoint is not denied for a whole cycle.
- [x] 2. `engineBinaryIntegrity`: three states, every failure path UNCHECKED, re-checked per report.
- [x] 3. Absent key → startup line naming the consequence; unusable key → fatal.
- [x] 4. Declare `OPENSHIELD_POSTURE_SIGNING_KEY` / `_INTERVAL` on `EngineFields`.
- [x] 5. Integration test: real gateway + real engine, BLOCKED before and ALLOWED after.
- [x] 6. Integration test: the no-key line says what it costs.
- [x] 7. Mutation: no posture producer.
- [x] 8. Docs: D476 row, roadmap table updated.
