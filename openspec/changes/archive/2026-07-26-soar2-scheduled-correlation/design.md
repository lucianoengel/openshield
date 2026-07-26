## Context

`MaterializeIncidents` and `MaterializeCrossDomainIncidents` are called from exactly one place each:
`incidentsHandler`. Nothing else in the tree calls them. `Leader.Run(ctx, onElected)` already gives a
leader-scoped context (PLAT-2b), and `retain.Loop(ctx, interval, fn)` already gives a cancellable ticker.
`incidents.state` today is `open` or `acknowledged`, and the open-incident uniqueness indexes are partial on
`state = 'open'`.

## Goals / Non-Goals

**Goals:** correlate on a clock, leader-only; a forward-only attributed lifecycle; refuse invalid
transitions.

**Non-Goals:** acting on incidents (SOAR-4/5/7/8), escalation timers and routing (SOAR-9), reopening,
backfill.

## Decisions

### D-1: The loop runs inside the leader's context

`Leader.Run` hands a context that is cancelled when leadership is lost, so the loop stops the moment this
instance stops being leader. Gating on a boolean checked at tick time would leave a window where a
demoted instance still materializes — and materialization pages.

### D-2: `acknowledged` stays the first post-open state

The lifecycle is `open → acknowledged → triaged → contained → closed` rather than replacing `acknowledged`
with `triaged`. `AcknowledgeIncident` and its first-ack-wins semantics (SIEM-11b) keep working unchanged,
and the new states extend rather than reinterpret what is already stored. Renaming a state that exists in
live rows would be a migration of meaning, not of schema.

### D-3: Forward-only, enforced by rank comparison

Each state has a rank; a transition is valid iff the target rank is strictly greater. No reopen.

The alternative — allowing `closed → open` — was rejected because MTTA/MTTR (SOAR-6) are derived from these
timestamps, and a lifecycle that can move backwards makes them unmeasurable. An incident that needs
reopening should be a NEW incident, which the partial-unique-on-open indexes already permit once the old one
leaves `open`.

### D-4: The uniqueness indexes need no change

They are partial on `state = 'open'`. Every new state is outside that predicate, so an incident that
advances frees its subject/entity for a future incident — exactly the existing behavior for
`acknowledged`.

## Risks / Trade-offs

- **The loop pages on its own now.** That is the point, and it means a noisy rule pages without anyone
  having asked. Mitigated by the existing per-incident page-once behavior (D220) and by the interval being
  operator-set; alert-storm suppression remains XDR-4's noted gap.
- **Leader-only correlation means no correlation while an election is in flight.** Bounded by the lease and
  acceptable: a delayed incident is better than duplicated pages.
- **Forward-only will annoy someone** who wants to reopen. Documented, with "raise a new incident" as the
  answer.

## Migration Plan

One additive migration for the transition columns; existing rows keep their state. No index change.
