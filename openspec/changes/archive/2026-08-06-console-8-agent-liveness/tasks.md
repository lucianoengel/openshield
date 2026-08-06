# Tasks — CONSOLE-8 increment 2

- [x] 1. `internal/buildinfo.Version` (default "dev"); `release.sh` stamps `$VERSION_SYMBOL`.
- [x] 2. `internal/doccheck` guard: the stamped symbol resolves to a real variable, and the script still
      stamps one. Mutation-verified against the exact bug that shipped.
- [x] 3. Proto: `Heartbeat` += `platform`, `agent_version`, `spool_depth` (additive, 6–8). Regenerate.
- [x] 4. `SignedPublisher.SpoolDepth()`; `Engine.AppliedFleetSequence()`.
- [x] 5. `openshield-engine`: `startHeartbeat` — interval, actual kill-switch state, applied sequence,
      inventory. Off is loud; a publish failure is logged, never fatal, never spooled.
- [x] 6. Migration `052`: `agent_enforcement` += the three inventory columns, NULLABLE with no default.
- [x] 7. `recordEnforcementState` stores an unreported field as NULL rather than its proto zero value.
- [x] 8. **`handleSigned` projects the acknowledgement for `kind == "heartbeat"`, verified path only** —
      the projection had no producer at all.
- [x] 9. Roster surfaces the inventory as pointers.
- [x] 10. Package tests + mutations; integration test running the REAL engine with an empty watch dir.
- [x] 11. Docs: decision row, roadmap, the simulator-vs-product finding table.
