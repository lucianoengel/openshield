# Tasks — SEC-B persistent replay bound

- [x] 1. `intent.NewPersistentFleetControlSubscriber` — load the bound, prove it writable, refuse a
      corrupt one.
- [x] 2. Persist BEFORE applying; refuse the control when the write fails; leave the in-memory bound
      un-advanced so memory and disk cannot disagree.
- [x] 3. `intent.OpenReplayBound` — path guard against sharing `OPENSHIELD_SEQ_FILE` (compared as
      absolute paths, not strings), read/write probe, `ErrBoundUnwritable` for the one downgradable
      failure.
- [x] 4. `SubscribeFleetControl` takes the bound on both the engine and the gateway; nil keeps the
      in-memory behaviour and the caller owes a startup warning.
- [x] 5. `OPENSHIELD_FLEET_CONTROL_SEQ_FILE` in both binaries with a DEFAULT path, `LookupEnv` so
      "deliberately empty" is expressible, and the explicit-vs-default failure distinction.
- [x] 6. Declared in `EngineFields` and `GatewayFields`, with different defaults so a host running
      both does not share one file.
- [x] 7. Unit tests: restart refuses a replay; persist-before-apply; corrupt refuses to start and is
      not downgradable; the writability probe; the shared-file guard; the in-memory constructor still
      works.
- [x] 8. Mutation-verify all seven.
- [x] 9. Integration: capture the control plane's own bytes, restart the gateway, replay — with an
      in-memory gateway as the control group proving the ammunition is live, and a freshly-issued
      control proving the channel still delivers to the restarted process.
- [x] 10. Fix `prepareForWriting` — an anchored ledger with no entries could not be reopened (blocked
      the restart scenario).
- [x] 11. Fix `reportDegraded` reachability — the gateway's degraded counters were reported only in
      access mode (blocked the "and it was counted" assertion).
- [x] 12. Correct `docs/threat-model.md`, including the in-memory residual.
- [x] 13. Spec delta + roadmap.
