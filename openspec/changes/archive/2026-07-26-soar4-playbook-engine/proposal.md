## Why

SOAR-2 (D250) made incidents raise and page on a clock, and SOAR-3 (D251) made four-eyes approval a
reusable object. What still does not exist is anything that *acts on* an incident: it is raised, it is
paged, and then a human does the same first-response sequence by hand every time — gather what is
already known, notify the right people, open a case, place a hold on the subject's evidence, tag it.
Automating that repetitive sequence is the difference between an alert queue and an orchestrated
response, and it is the remaining gap the roadmap names for the SOAR lane's spine
(SOAR-2 → SOAR-3 → **SOAR-4** → SOAR-5/7 → SOAR-8).

## What Changes

- **A declarative playbook**: a *trigger* (minimum incident severity, incident kinds, incident domains)
  plus an **ordered list** of steps drawn from a **closed step registry** — `enrich`, `notify`,
  `open-case`, `place-hold`, `tag`, `annotate`, `wait-for-approval`. A step name outside the registry is
  **refused at load**, not at execution. The registry is closed for exactly the D14 reason the Action set
  and the intent vocabulary are: a playbook must not be able to express an arbitrary operation, or a
  compromised control plane — or a careless operator editing config — could make the server run anything.
- **No actuation steps in v1** (ADR-12 Tier-1, explicitly). Nothing here blocks a flow, kills a process,
  disables a user, or publishes a `ResponseIntent`. Actuation is Tier-2/Tier-3: SOAR-7 shipped the signed
  intent seam with four-eyes and blast-radius gating, and SOAR-8 owns the integration runners. A playbook
  that could actuate without those controls would bypass exactly the gating those tickets exist to enforce.
- **Durable, resumable run state** in Postgres (`playbook_runs` + `playbook_steps`, migration 032). Killing
  the control plane mid-run and restarting resumes at the first unfinished step, and **a step that already
  completed is not re-run**. Idempotency is the property that matters: a re-notified incident or a second
  case is precisely the failure that makes operators stop trusting automation.
- **`wait-for-approval` becomes the first automation consumer of SOAR-3's approvals object**, whose only
  caller until now was case closure. The step opens an approval bound to `<run-id>:<seq>` and **parks** the
  run; a later tick resumes it on approval and **fails the run** on denial or expiry.
- **Leader-only execution**, in the same elected context `RunCorrelationLoop` uses (ADR-3/PLAT-2b). Every
  replica running playbooks would multiply notifications, cases and holds.
- **Every step transition is durably recorded** with its outcome and timing — the same timestamps SOAR-6
  will derive analyst metrics from.
- New table `incident_annotations` carries what `enrich`, `tag` and `annotate` produce, so a playbook's
  work is visible on the incident rather than only in the run log.

Not breaking: the loop is off unless `OPENSHIELD_PLAYBOOKS` names a config file.

## Capabilities

### New Capabilities
- `playbook-orchestration`: declarative incident playbooks over a closed, non-actuating step registry,
  with durable resumable run state and leader-only execution.

### Modified Capabilities
- `four-eyes-approvals`: adds the requirement that an approval requested by *automation* (a playbook step)
  records the playbook as requester and requires a human approver — and that the requesting feature, not
  the approval object, decides what a denial or expiry means.

## Impact

- **New code**: `internal/controlplane/playbook.go` (types, closed registry, loader, engine),
  `internal/controlplane/playbook_steps.go` (the seven step implementations).
- **Migration 032**: `playbook_runs`, `playbook_steps`, `incident_annotations`. Additive; no existing
  table is altered.
- **Wiring**: `cmd/openshield-server` starts `RunPlaybookLoop` inside the leader context when
  `OPENSHIELD_PLAYBOOKS` is set.
- **No proto change, no new dependency, no change to the frozen pipeline.** The engine reads incidents and
  writes annotations, cases, holds, notifications and its own run state — all server-side.
- **Honest scope** (stated in the spec and the decision record): no actuation; no branching/DAG (v1 is an
  ordered list — a DAG's failure semantics deserve their own decision rather than a guess); no retries,
  backoff or scheduling beyond the approval TTL; no playbook editing UI (PLAT-1) and no per-tenant playbook
  library; and the step set is small on purpose so each addition is deliberate rather than a plugin surface.
