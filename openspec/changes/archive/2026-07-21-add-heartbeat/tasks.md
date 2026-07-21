## 1. Heartbeat plumbing

- [x] 1.1 `Heartbeat` proto message + regenerate (agent_id, sequence, observed_at)
- [x] 1.2 `SubjectHeartbeat` + `PublishHeartbeat` on the nats transport (concrete type, NOT the
      core.Transport interface — core stays minimal)
- [x] 1.3 Control plane subscribes to heartbeats and records each as a fleet_telemetry row
      (kind="heartbeat"), so last-seen updates uniformly

## 2. Last-seen + dead-man's-switch

- [x] 2.1 `LastSeen(ctx, agentID)` = max(received_at) for the agent
- [x] 2.2 Pure detector `OverdueAgents(statuses, threshold, now) []AgentStatus`
- [x] 2.3 `Overdue(ctx, threshold, now)` reads per-agent last-seen and applies the detector

## 3. Tests

- [x] 3.1 **Test**: a heartbeat over embedded NATS advances last-seen. `TestHeartbeatUpdatesLastSeen`
- [x] 3.2 **Test**: the pure detector marks a long-silent agent overdue and a recent one not (table).
      `TestDeadMansSwitch`
- [x] 3.3 **Test**: `Overdue` end to end — one stale, one fresh agent → only the stale is overdue.
      `TestOverdueEndToEnd`

## 4. Stop record + docs

- [x] 4.1 `deploy/openshield-agent.service` drop-in with an `ExecStopPost` hook that records a clean
      stop (documented; recording path is the heartbeat/telemetry already built)
- [x] 4.2 Note in `docs/decisions.md` (new D-number): dead-man's-switch reports OVERDUE not tampered;
      clean stop recorded so silence-with-no-stop stands out; defeatable by root / compromised
      control plane; backs D16
- [x] 4.3 Mark T-018 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| detector never marks overdue | `TestDeadMansSwitch` |
| heartbeat recorded under the wrong (empty) agent | `TestHeartbeatUpdatesLastSeen` |

The dead-man's-switch is a pure function tested at its boundary (fresh /
edge-under / edge-over / stale). End to end over embedded NATS: a heartbeat
advances last-seen (`TestHeartbeatUpdatesLastSeen`), an unknown agent is not
found, and `Overdue` flags a backdated agent while sparing a fresh one
(`TestOverdueEndToEnd`). A clean-stop `ExecStopPost` hook ships in `deploy/` so
silence-with-no-stop is the case that stands out. Every surface states the D16
limit: defeatable by root / a compromised control plane; overdue is a signal, not
an accusation.
