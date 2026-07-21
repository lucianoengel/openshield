## Context

The control plane (T-023) already stores `fleet_telemetry(agent_id, kind, received_at, ...)`, so
"when did we last hear from agent X" is derivable as `max(received_at)`. What is missing: an idle
agent (nothing to report) still needs to check in, and something must flag a host that has gone
silent. A `Heartbeat` proto message and subject now exist.

## Goals / Non-Goals

**Goals:**
- Agent heartbeat updates "last seen"; control plane tracks it per host.
- A dead-man's-switch: a pure detector that reports OVERDUE agents given last-seen + a threshold.
- A clean stop is itself recorded, so silence-with-no-stop is the case that stands out.

**Non-Goals:**
- Preventing tampering (D16); tamper-evidence on the aggregate (D41); alert routing / automated
  response; distinguishing legitimate sleep from tampering (overdue is a signal, not an accusation).

## Decisions

### Heartbeat rides its own subject; last-seen is aggregate-derived
`SubjectHeartbeat = "openshield.v1.heartbeats"`. The nats transport gains `PublishHeartbeat`
(on the concrete type, NOT the core.Transport interface — core stays minimal, and a heartbeat is
an operational signal, not pipeline telemetry). The control plane subscribes and records each
heartbeat as a `fleet_telemetry` row with kind="heartbeat", so last-seen updates uniformly whether
the agent reported real telemetry or just a heartbeat. `LastSeen(agentID)` = max(received_at).

### The dead-man's-switch is a pure detector
`OverdueAgents(statuses []AgentStatus, threshold, now) []AgentStatus` where an agent is overdue if
`now - lastSeen > threshold`. Pure over timestamps, tested directly with no DB — the logic that
decides "someone should look" must be trivially verifiable. The control plane's
`Overdue(ctx, threshold)` reads last-seen per agent from the store and applies it.

Overdue reports a SIGNAL, not an accusation: the offline queue (T-024) means a briefly-offline
agent's telemetry arrives on reconnect, so a short gap self-heals; sustained silence past the
threshold is what surfaces. The threshold should be several heartbeat intervals so normal jitter
does not cry wolf — stated where it is configured.

### A clean stop is recorded
`deploy/openshield-agent.service` gains `ExecStopPost=` invoking a small `openshieldctl`-style
record (or a hook that publishes a "stopped" heartbeat/telemetry), so `systemctl stop` leaves a
trail. The distinction that matters: "stopped cleanly (a stop record exists)" is benign; "silent
past threshold with no stop record" is the suspicious case. In Phase 1 the hook is documented and
the recording path is the heartbeat/telemetry already built; wiring the exact unit is packaging
(T-027), so this change specifies the hook and provides the drop-in.

## Risks / Trade-offs

- **Defeatable by root and by a compromised control plane** (D16, D41). Root can stop the agent and
  suppress the heartbeat; a compromised control plane can forge one. The narrow, honest value is
  detecting the COMMON case (agent died / was stopped / host went offline), not defeating an
  adversary who owns both ends. Stated on every surface.
- **Silence is ambiguous.** Overdue ≠ tampered. Reported as a signal for a human; the threshold is
  tuned to avoid false alarms from normal offline periods.
- **Last-seen lives in the non-evidentiary aggregate.** By design; the evidentiary record is the
  agent ledger. The heartbeat is operational monitoring, not evidence.
