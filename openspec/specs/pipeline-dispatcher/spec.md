# Pipeline Dispatcher

## Purpose

The in-process, synchronous stage runner on the endpoint. Stages know nothing about each other; the dispatcher owns ordering, deadlines and failure reporting. In-process by measurement, not preference — see D24.

> Synced from change `add-pipeline-dispatcher` on 2026-07-20.
> Implemented in `internal/core` and `internal/transport/nats`; invariants
> mutation-tested (see the change's tasks.md).

## Requirements
### Requirement: Stages are registered, not wired
The dispatcher SHALL execute an ordered sequence of stages obtained from a registry. A stage
SHALL NOT reference, import or name any other stage. Adding or removing a stage SHALL require no
edit to any other stage.

This is the whole architectural bet in executable form: if adding a capability means editing the
core or another stage, the ten-year claim is false.

#### Scenario: A stage can be added without touching another stage
- **WHEN** a new stage is registered between Classification and Policy
- **THEN** the pipeline executes it in order
- **AND** no source file belonging to another stage is modified
- **AND** a test asserts this by registering a stage from the test package alone

#### Scenario: Stages cannot reach each other
- **WHEN** the stage interface is inspected
- **THEN** it exposes no registry, no sibling handle and no dispatcher reference through which
  one stage could locate another

### Requirement: The dispatcher terminates deterministically
Given the same input Event and the same registered stages, the dispatcher SHALL produce the same
Decision. Stage execution SHALL be ordered and single-pass; a stage SHALL NOT re-enter the
pipeline.

#### Scenario: Same input yields the same Decision
- **WHEN** the same Event is dispatched twice through an identically configured pipeline
- **THEN** both runs produce Decisions equal in action, confidence, reason and policy identity

#### Scenario: Re-entry is refused
- **WHEN** a stage attempts to dispatch an Event from within the pipeline
- **THEN** the attempt is refused rather than recursing

### Requirement: A stage failure is contained and audited
When a stage returns an error the dispatcher SHALL NOT silently drop the Event. It SHALL produce
a terminal outcome recording which stage failed, and that outcome SHALL reach the audit path.

Silence is the failure mode that makes a DLP tool worse than useless: an operator cannot
distinguish "nothing sensitive happened" from "the classifier crashed".

#### Scenario: A failing stage produces an auditable outcome
- **WHEN** a registered stage returns an error
- **THEN** the dispatcher emits an outcome naming the failed stage
- **AND** the Event is not silently discarded
- **AND** a test asserts the audit path received exactly one record for that Event

### Requirement: Stage execution is bounded by a deadline
Every stage invocation SHALL be governed by a context deadline. On expiry the dispatcher SHALL
terminate the pipeline for that Event and emit a **high-severity** timeout outcome.

An unbounded stage is the mechanism by which the fanotify responder hangs a machine — the
failure mode T-002 identified as the real risk, as distinct from the GC pause it measured and
exonerated. Fail-open is the correct behaviour and is itself a bypass, so it is never silent
(D17).

#### Scenario: A slow stage does not stall the pipeline
- **WHEN** a stage exceeds its deadline
- **THEN** the dispatcher abandons that Event's pipeline within the deadline
- **AND** emits a timeout outcome marked high severity
- **AND** a test asserts the outcome is severity-marked, not merely present — a quiet
  timeout is indistinguishable from a clean allow

#### Scenario: Timeout rate is observable
- **WHEN** timeouts occur
- **THEN** a counter distinguishes them from ordinary outcomes, so a rising rate is detectable
  as its own signal rather than being averaged away

### Requirement: The core does not depend on a broker
`internal/core` SHALL NOT import any message broker client. Transport SHALL be reached through
an interface defined in core and implemented elsewhere.

The endpoint pipeline is in-process and synchronous by measurement: T-002 established a 1-3µs
typical and 532µs worst-case budget for the fanotify permission window, which a broker round
trip does not fit. Keeping the dependency out of core is what stops that boundary eroding.

#### Scenario: Core has no broker dependency
- **WHEN** the dependency graph of `internal/core` is computed by CI
- **THEN** it contains no NATS client and no network transport package
- **AND** the check fails the build rather than warning
