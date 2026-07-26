## 1. Acknowledgement
- [x] 1.1 Two additive `Heartbeat` fields: actual enforcement state + applied fleet sequence.
- [x] 1.2 Migration `037_agent_enforcement.sql` (projection, latest-wins upsert).
- [x] 1.3 Project on every heartbeat, best-effort — a projection failure must not cost the fleet its
      liveness signal.
- [x] 1.4 `FleetEnforcementState(target)`: agents / disabled / enforcing / not-caught-up.

## 2. Tests
- [x] 2.1 Disabled and enforcing agents are counted; lag against the target sequence is counted
      (**mutation:** do not project → the summary stays empty → FAILS).
- [x] 2.2 The LATEST report wins and an agent is counted once (**mutation:** DO NOTHING on conflict →
      stale state persists → FAILS).
- [x] 2.3 A locally-disabled agent (applied sequence 0) is visible.

## 3. Gate and land
- [x] 3.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.2 Record D270; roadmap residual closed.
- [x] 3.3 Sync specs and archive.
