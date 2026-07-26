## 1. Schema

- [x] 1.1 Migration `032_playbooks.sql`: `playbook_runs` (unique on `(playbook, incident_id)`),
      `playbook_steps` (PK `(run_id, seq)`, state, approval_id, result, timings, error), and
      `incident_annotations` (incident_id, kind, body, author, created_at + read index). Additive only.
- [x] 1.2 Add the three tables to every test drop-list that resets the schema (controlplane, postgres, xdr),
      since shared-DB tables otherwise accumulate across runs.

## 2. Playbook model and closed registry

- [x] 2.1 `internal/controlplane/playbook.go`: `StepName` constants (the seven Tier-1 names), `Step`,
      `Trigger`, `Playbook`, run/step state constants.
- [x] 2.2 `playbookSteps` registry map; `LoadPlaybooks(io.Reader)` parsing operator JSON and validating:
      non-empty name, at least one step, known severity floor, **every step name present in the registry**,
      and per-step argument rules (tag charset/length, annotation length, no argument where none is taken).
- [x] 2.3 Test: an unknown step name is refused at LOAD with the offending name in the error.
      **Mutation:** drop the registry membership check → an unknown step loads → test FAILS.
- [x] 2.4 Test: the declared vocabulary and the registry key set are identical in both directions.
- [x] 2.5 Test: the registry contains exactly the seven Tier-1 names (an actuating addition cannot pass
      unnoticed), and the engine source contains no call to intent publication or enforcement.

## 3. Step implementations (non-actuating)

- [x] 3.1 `internal/controlplane/playbook_steps.go`: `enrich` (local context assembly → annotation),
      `notify` (existing fanout, dedupe id `pb_<run>_<seq>`), `open-case` (`OpenCaseForIncident`,
      attributed `playbook:<name>`), `place-hold` (legal hold via the pool), `tag`, `annotate`.
- [x] 3.2 `wait-for-approval`: open an approval with subject kind `playbook-step`, subject id
      `<runID>:<seq>`, requester `playbook:<name>`; return the waiting sentinel; on resume read
      `ApprovalFor` and complete / fail / stay parked.

## 4. Engine

- [x] 4.1 `RunPlaybooksOnce`: resume `running` and `waiting` runs first, then start runs for matching
      incidents (severity floor via `severityFloor`, kinds, domains, `NOT EXISTS` on the run pair).
- [x] 4.2 `executeRun`: for each step, SQL-claim it (`state <> 'done'`), execute, record outcome+timing;
      a failing step fails the run and stops; a waiting step parks the run.
- [x] 4.3 `RunPlaybookLoop` over `retain.Loop` with a `PlaybookFailures` counter, mirroring
      `RunCorrelationLoop`; wire it into `cmd/openshield-server` inside the leader context behind
      `OPENSHIELD_PLAYBOOKS` (+ `OPENSHIELD_PLAYBOOK_INTERVAL`).

## 5. Tests (real Postgres)

- [x] 5.1 A high-severity incident auto-runs `enrich→notify→open-case` in declared order, each effect
      observable; the run ends `succeeded`.
- [x] 5.2 A non-matching incident (below the floor / wrong kind) starts no run.
- [x] 5.3 Repeated ticks after success leave exactly one run and one set of effects.
- [x] 5.4 **Resumption:** interrupt a run after step 1, restart the engine, assert it continues at step 2 and
      step 1's annotation exists **exactly once**. **Mutation:** remove `AND state <> 'done'` from the claim
      → the step re-runs → test FAILS. (Assert on annotations, never on the deduped notification.)
- [x] 5.5 `wait-for-approval`: the run parks with a pending approval and no later step executed; an operator
      approval resumes it to completion; a denial fails the run; an expired request fails the run.
- [x] 5.6 A failing step fails the run and leaves later steps pending.
- [x] 5.7 Loop behaviour: a cancelled (leader) context stops the loop; a failing tick increments
      `PlaybookFailures` without stopping it.

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 6.2 Record the decision (D256) in `docs/decisions.md` with the honest scope: no actuation, no DAG, no
      retries, one-operator human gate (not two-human four-eyes), enrichment is local context assembly.
- [x] 6.3 Update `docs/architecture-roadmap.md`: SOAR-4 → DONE with its residuals; refresh the SOAR maturity
      line.
- [x] 6.4 Sync delta specs into `openspec/specs/` and archive the change.
