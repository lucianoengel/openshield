# playbook-orchestration Specification

## Purpose
Declarative incident playbooks (SOAR-4, ADR-12 Tier-1): a trigger plus an ORDERED LIST of steps drawn from
a CLOSED registry, executed by the elected leader with durable, resumable state. The engine turns a raised
incident into the first-response sequence an analyst would otherwise repeat by hand. It gathers, records
and notifies — it does not actuate, because actuation belongs behind SOAR-7's four-eyes-and-blast-radius
gating and SOAR-8's per-connector verb sets.


### Requirement: Declarative playbooks over a closed step registry

The control plane SHALL execute *playbooks*: a named trigger plus an ordered list of steps. Every step
name MUST come from a closed registry — `enrich`, `notify`, `open-case`, `place-hold`, `tag`, `annotate`,
`wait-for-approval`. A playbook naming a step outside that registry MUST be refused **at load time**, so a
malformed or hostile configuration never reaches execution. The registry is closed for the same reason the
Action set (D14) and the response-intent verb set are closed: a playbook must not be able to express an
arbitrary operation.

#### Scenario: A playbook naming an unknown step is refused at load
- **WHEN** a playbook configuration contains a step named `exfiltrate` (or any name absent from the registry)
- **THEN** loading MUST fail with an error naming the offending step
- **AND** no run is created and no step is executed

#### Scenario: A playbook naming only registry steps loads
- **WHEN** a playbook lists `enrich`, `notify`, `open-case`
- **THEN** loading succeeds and the steps retain their declared order

#### Scenario: Registry and step-name vocabulary cannot drift apart
- **WHEN** the declared step-name vocabulary is compared with the registry's implementations
- **THEN** the two sets MUST be identical — a declared name with no implementation, or an implementation
  with no declared name, is a failure

### Requirement: No actuation in playbook v1

A playbook step SHALL NOT actuate. No step may block a flow, terminate a process, disable a user, change
enforcement, or publish a `ResponseIntent`. v1 is ADR-12 **Tier-1**: it gathers, records and notifies.
Actuation belongs to the Tier-2 signed intent seam (SOAR-7), which gates publication on four-eyes and a
blast-radius ceiling, and to the Tier-3 integration runners (SOAR-8). A playbook able to actuate without
those gates would bypass exactly the controls they exist to enforce.

#### Scenario: The registry contains no actuating step
- **WHEN** the step registry's key set is enumerated
- **THEN** it MUST equal exactly the seven Tier-1 names, so adding an actuating step cannot pass unnoticed

#### Scenario: The engine does not reach the intent publisher
- **WHEN** the playbook engine's source is inspected for calls to intent publication or enforcement
- **THEN** none are present

### Requirement: Triggering on incident severity, kind and domain

A playbook SHALL declare a trigger over an incident's **minimum severity**, its **kinds**, and its
**domains**. An incident matches when its severity is at or above the floor and (when the trigger
constrains them) its kind and at least one of its domains are listed. An incident that does not match MUST
NOT start a run. A playbook SHALL start **at most one run per incident**, enforced by the database, so a
repeated scheduling tick cannot start the same work twice.

#### Scenario: A high-severity incident starts a run
- **WHEN** the scheduled engine runs and an open incident's severity is at or above the playbook's floor
- **THEN** a run is created for that (playbook, incident) pair and its steps execute in declared order

#### Scenario: A non-matching incident starts nothing
- **WHEN** an incident's severity is below the playbook's floor, or its kind is not among the trigger's kinds
- **THEN** no run exists for that (playbook, incident) pair

#### Scenario: Repeated ticks do not restart a completed run
- **WHEN** the engine runs many further ticks after a run has succeeded
- **THEN** exactly one run exists for that (playbook, incident) pair and its steps executed once

### Requirement: Durable, resumable run state without duplicating a step

Run and step state SHALL be durable in the database and updated as each step transitions, so a control
plane killed mid-run resumes on restart at the first unfinished step. A step recorded as **done** MUST NOT
be executed again, and that guard MUST be enforced atomically by the database claim that starts a step —
not by an in-memory decision, which a crash erases.

#### Scenario: An interrupted run resumes at the next step
- **WHEN** a run is interrupted after its first step completes, and the engine is restarted
- **THEN** the run continues at the second step and reaches completion

#### Scenario: A completed step's effect happens exactly once
- **WHEN** an interrupted run is resumed
- **THEN** the already-completed step's observable effect (its annotation, its case, its page) is present
  exactly once — never twice

#### Scenario: Every step transition is recorded with its outcome and timing
- **WHEN** a run finishes
- **THEN** each step carries its final state, start time and finish time, and a failed step carries its error

### Requirement: A failing step fails the run

A step that returns an error SHALL fail the run: the step is recorded as failed with its error, the run is
recorded as failed, and no later step executes. v1 performs no retries and no backoff — an operator
inspects the failure and re-runs. A half-executed sequence that silently continued would produce a case
whose enrichment never happened, which is worse than a visible failure.

#### Scenario: A failing step stops the sequence
- **WHEN** a step returns an error
- **THEN** the run's state is `failed`, the failing step records the error, and subsequent steps stay pending

### Requirement: wait-for-approval parks the run for a human

A `wait-for-approval` step SHALL open an approval request bound to that run and step, park the run, and
resume only when a human resolves it. On **approval** the run continues at the next step. On **denial or
expiry** the run fails. A parked run MUST NOT proceed on its own.

#### Scenario: The run parks until approved
- **WHEN** a run reaches a `wait-for-approval` step
- **THEN** an approval request exists for that run and step, the run's state is `waiting`, and no later step
  has executed

#### Scenario: Approval resumes the run
- **WHEN** an operator approves the pending request and the engine ticks again
- **THEN** the step is recorded done and the remaining steps execute

#### Scenario: Denial or expiry fails the run
- **WHEN** the request is denied, or its TTL elapses without a decision
- **THEN** the run's state becomes `failed` and no later step executes

### Requirement: Leader-only execution

The playbook engine SHALL run inside the elected leader's context (ADR-3/PLAT-2b), like scheduled
correlation. Every replica executing playbooks would multiply notifications, cases and legal holds. A tick
that errors SHALL be counted and logged but MUST NOT stop the loop — one bad run must not end orchestration
for the process lifetime.

#### Scenario: Loss of leadership stops execution
- **WHEN** the leader context is cancelled
- **THEN** the playbook loop stops rather than continuing to the next tick

#### Scenario: A failing tick does not stop the loop
- **WHEN** one tick returns an error
- **THEN** a failure counter increments and later ticks still execute

### Requirement: Enrichment performs a threat-intel lookup against the IOC store

The `enrich` step SHALL resolve each contributing alert's evidence to the originating event, extract the
network observables that event already carries, match them against the IOC store, and record a `ti`
annotation naming the matched indicator and the feed that asserted it. An incident with no match SHALL
receive no `ti` annotation — an annotation that says "nothing found" trains an analyst to skip them.

#### Scenario: A known-bad destination is annotated
- **WHEN** an incident's alert has evidence naming a destination that matches an indicator
- **THEN** a `ti` annotation records the matched indicator and its feed

#### Scenario: A clean incident gets no threat-intel annotation
- **WHEN** no observable matches any indicator
- **THEN** no `ti` annotation is written

### Requirement: Only verified evidence may steer enrichment

Enrichment SHALL read observables only from events recorded as VERIFIED (D44). Unverified telemetry is
not evidence, and allowing it to decide that an incident is threat-intel-confirmed would let anyone able
to publish unsigned telemetry manufacture confidence in — or distract from — an incident.

#### Scenario: An unverified event carrying a known-bad destination is ignored
- **WHEN** the only event naming a matching destination is not verified
- **THEN** no `ti` annotation is written

### Requirement: A threat-intel hit is context, never enforcement

A threat-intel match SHALL annotate only. It MUST NOT raise an alert, change an incident's severity,
advance its lifecycle, or actuate. Turning public threat intelligence into automatic enforcement is how a
poisoned or over-broad feed becomes a denial of service.

#### Scenario: A match changes nothing but the annotation
- **WHEN** enrichment records a threat-intel match
- **THEN** the incident's severity, state and alert set are unchanged
