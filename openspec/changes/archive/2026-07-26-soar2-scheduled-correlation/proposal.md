## Why

Correlation only runs when an operator asks for it. Both materializers are called from inside the
`GET /incidents` handler and nowhere else — so an incident exists only if a human happens to look, and
SOAR-1's "a materialized incident pages once, automatically" (D220) is automatic only in the sense that the
page follows the materialization. Nobody looking means nobody paged.

That is the difference between a SIEM view and a SOC: detection has to run on a clock.

The incident lifecycle is also thinner than the work it has to carry. An incident is `open` or
`acknowledged`; there is no way to record that it was triaged, that containment happened, or that it was
closed — which is exactly the state SOAR's playbooks, metrics (MTTA/MTTR) and approvals will need.

## What Changes

- **Correlation runs on a schedule.** A loop materializes both rules — the single-domain burst rule and the
  XDR-4 cross-domain rule — on an interval, so an incident is raised and paged without anyone looking.
- **Only the leader correlates.** The control plane already elects a leader (PLAT-2b/ADR-3); every replica
  running the loop would multiply materializations and pages.
- **A real incident lifecycle:** `open → acknowledged → triaged → contained → closed`, forward-only, each
  transition recording who made it and when. Invalid transitions are refused rather than silently applied.
- **An operator endpoint to advance an incident**, gated on the responder tier like the existing ack.

## Capabilities

### Modified Capabilities

- `control-plane`: correlation is scheduled rather than request-triggered, and incidents carry a full
  forward-only lifecycle with attributed transitions.

## Impact

- **Code:** `internal/controlplane` (a scheduled loop, the transition state machine, one route),
  `cmd/openshield-server` wiring, one migration for the transition columns.
- **Decisions:** extends **ADR-10** (the alert/incident lifecycle), depends on **ADR-3/PLAT-2b** (leader
  election) and **D220/SOAR-1** (page once per materialized incident).

### What this change does NOT claim or cover

- **It does not act on an incident.** Scheduling correlation raises and pages incidents; playbooks
  (SOAR-4), enrichment (SOAR-5) and response (SOAR-7/8) are separate tickets. `contained` is a state a human
  records, not something this ticket performs.
- It does **not** add escalation timers, on-call routing, or reminders for an incident nobody touches —
  SOAR-9 owns routing, and overdue-incident escalation is not in this ticket.
- Transitions are **forward-only**: there is no reopen. An incident that needs reopening gets a new
  incident, because a lifecycle that can go backwards makes MTTA/MTTR meaningless.
- The loop correlates over the configured window on each tick; it does not backfill history, so incidents
  are only ever raised from alerts inside the current window.
