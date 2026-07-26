## Context

Incidents are already raised on a clock and paged automatically (SOAR-2/D250), and four-eyes approval is a
reusable object keyed by `(subject_kind, subject_id)` (SOAR-3/D251) whose only caller is case closure. The
pieces a playbook needs already exist as server methods: `OpenCaseForIncident`, `placeLegalHoldTx`, `emit`
(the notification fanout with durable dedupe), and the incident/alert/entity tables the timeline reads.
What is missing is the thing that *sequences* them, durably, without duplicating work across a restart.

Constraints in force:
- The step vocabulary must be **closed** (D14's threat by another door: a compromised control plane or a
  careless operator must not be able to express an arbitrary operation as configuration).
- v1 is ADR-12 **Tier-1** — no actuation.
- Singleton work runs under the leader lease (ADR-3/PLAT-2b).
- Migration 001 warns that adding a column to `audit_entries` breaks hash-chain continuity, so nothing here
  touches the ledger's hashed content.

## Goals / Non-Goals

**Goals:**
- A declarative playbook = trigger + ordered step list, validated at load against a closed registry.
- Durable run/step state such that a control plane killed mid-run resumes at the first unfinished step and
  **never re-executes a completed one**.
- `wait-for-approval` as the first automation consumer of the SOAR-3 approvals object.
- Leader-only, ticking execution with a failure counter, matching `RunCorrelationLoop`'s shape.
- Step transitions recorded with outcome and timing — the raw material for SOAR-6's analyst metrics.

**Non-Goals:**
- **Any actuation.** No blocking, killing, disabling, or intent publication (SOAR-7/8 own that, with the
  four-eyes and blast-radius gating a playbook deliberately does not get).
- **Branching / DAG.** v1 is an ordered list. A DAG's failure semantics — what happens to sibling branches
  when one fails, whether a join waits or aborts — is a decision that deserves its own round, not a guess
  baked into a schema.
- Retries, backoff, per-step timeouts, or scheduling beyond the approval TTL.
- Threat-intel enrichment (SOAR-5 owns the IOC store, shared with NIPS-2).
- A playbook editing UI (PLAT-1) or a per-tenant playbook library. A playbook is operator-supplied
  configuration read at startup.
- Notification routing (SOAR-9). `notify` uses the existing fanout.

## Decisions

### The registry is a map, and the vocabulary is a closed enum checked against it

`playbookSteps map[StepName]stepFunc` with seven entries; `StepName` constants declare the vocabulary. The
loader refuses a name absent from the map. A test asserts the *two sets are identical in both directions* —
a declared name with no implementation and an implementation with no declared name are both failures. This
is the same discipline as `unifiedDomainFor` being total over the `EventKind` enum: the compiler cannot
enforce map totality, so a test does.

*Alternative rejected:* a plugin interface with registration. That is precisely the open action framework
D14 forbids — it moves the vocabulary from the binary to whatever registers, and "what can a playbook do"
stops being answerable by reading the source.

### The already-done guard lives in the SQL claim, not in Go

Each step is started by:

```sql
UPDATE playbook_steps SET state='running', started_at = coalesce(started_at, now())
 WHERE run_id=$1 AND seq=$2 AND state <> 'done'
```

Zero rows affected means the step is already done → skip it. Putting the guard in the claim rather than in
a Go `if` makes it survive both a crash (there is no in-memory state to lose) and an overlap of two
executors during a leader handover. It is also the single point the resumption mutation targets: removing
`AND state <> 'done'` re-runs a completed step, and the test must fail.

*Alternative rejected:* reading all step states into memory and filtering. Correct in the happy path, but
it puts the invariant one process crash away from being wrong, and a mutation of it is not obviously
load-bearing.

### One run per (playbook, incident), enforced by a unique index

`CREATE UNIQUE INDEX playbook_runs_once_idx ON playbook_runs (playbook, incident_id)`. The engine's
"start runs for matching incidents" query is `NOT EXISTS (…)` against the same pair, so the index is the
backstop rather than the mechanism — the pattern SOAR-1 already relies on for "pages exactly once."

### `wait-for-approval` parks the run rather than blocking a goroutine

The step returns a sentinel `errStepWaiting`; the run is recorded `waiting` and the executor returns. Each
tick resumes `running` **and** `waiting` runs: for a waiting step it reads `ApprovalFor(playbook-step,
"<runID>:<seq>")` and either completes the step (approved), fails the run (denied/expired), or leaves it
parked (pending). Nothing sleeps, nothing holds a connection, and a restart mid-wait is indistinguishable
from a tick.

**The honest bit, recorded because it is easy to overclaim:** the requester is the *playbook*, not an
operator, so requester≠approver cannot mean two humans. It is a **human-in-the-loop gate** — exactly one
operator approval — and is described that way in the spec, the code comment and the decision record. Using
an operator identity as requester would have been worse: it would attribute a machine's request to a human.

### Enrichment in v1 is local context assembly, not threat intel

`enrich` writes an `incident_annotations` row summarizing what the platform *already* holds about the
incident: alert count, distinct domains, window, and the entity's alias count when the incident is
entity-keyed. It reads no content and adds no external lookup. Naming it `enrich` while SOAR-5 is unbuilt
risks reading as more than it is, so both the code and the spec say what it does and does not do.

### `tag`/`annotate` carry an operator-supplied argument; `enrich` does not

`Step.Arg` is validated at load: a tag is `[a-z0-9][a-z0-9:_-]{0,63}`; an annotation is ≤512 characters.
Steps that take no argument reject a non-empty one at load. Config is operator-supplied, but a step whose
argument shape is unvalidated is where a "closed vocabulary" quietly stops being closed.

### Notification dedupe id is derived from run+step

`pb_<runID>_<seq>` through the existing durable dedupe. Defence in depth against a double page — and
deliberately **not** the property the resumption test asserts on, because dedupe would mask the mutation.
That trap already bit once (D242, where SIEM-12 dedupe made a duplicated projection pass its test). The
resumption test therefore counts `incident_annotations`, which nothing dedupes.

## Risks / Trade-offs

- **A playbook run does work an operator did not individually authorize** → the step set is non-actuating by
  construction, `open-case`/`place-hold` are reversible and attributed (`playbook:<name>`), and the loop is
  off unless `OPENSHIELD_PLAYBOOKS` is configured.
- **A misconfigured trigger opens cases in bulk** → the trigger's severity floor plus one-run-per-incident
  bound the blast radius, but a floor of `low` on a noisy fleet will open many cases. Named, not solved:
  rate-limiting playbook starts is a follow-up, not something to fake with a magic constant here.
- **A leader handover mid-run could overlap two executors** → the SQL claim makes a completed step
  un-re-runnable and a `running` step re-claimable; the worst case is a step whose *effect* landed but whose
  `done` write did not, repeating once. That residue is inherent without two-phase effects and is stated
  rather than papered over.
- **A run references a playbook the config no longer defines** → the tick skips it, counts it, and logs it,
  leaving the run visibly stuck rather than silently discarding operator-visible state.
- **`enrich` reads as threat intel** → mitigated by naming, not by mechanism; SOAR-5 replaces the body.

## Migration Plan

Migration 032 is purely additive (`playbook_runs`, `playbook_steps`, `incident_annotations`); no existing
table or index is altered, so a rollback is dropping three unused tables. The feature is inert until
`OPENSHIELD_PLAYBOOKS` points at a config file, so deploying the migration and the binary changes no
behaviour on its own.

## Open Questions

- Whether SOAR-9's routing table should apply to a playbook's `notify` step or only to incident paging —
  deferred to SOAR-9, which owns the routing decision.
- Whether a failed run should be operator-restartable in place or become a new run — v1 leaves it failed
  and visible; the answer follows from what SOAR-6's metrics need to count.
