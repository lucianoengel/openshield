## Context

`notify.Multi` fans one notification out to every configured sink (SIEM-8), with retry composed inside so
a retry re-attempts only the sink that failed. Sinks are anonymous URLs from a comma-separated
`OPENSHIELD_ALERT_WEBHOOK`. `controlplane.emit` is the single funnel every notification passes through
(dedupe, durable idempotency, the bounded queue), which makes it the one place to stamp a severity.

Three tickets deferred routing here. The one that matters most is SOAR-4: its `wait-for-approval` step
parks a run until a human resolves an approval, and nothing tells that human the approval exists.

## Goals / Non-Goals

**Goals:**
- Ordered kind/severity → named-sink rules, first match wins.
- A counted fail-open for notifications matching no rule.
- Severity on every notification, stamped in one place from the existing mapping.
- Notify on a pending approval, closing SOAR-3's residual and unblocking SOAR-4's gate in practice.

**Non-Goals:**
- **Templating.** Rendering operator-supplied templates over notification fields is an injection surface
  into whatever displays the result, and `Detail` is already a closed-vocabulary summary written by the
  producer. Per-sink formatting belongs in the receiver.
- Escalation ladders, on-call schedules, rotations, reminders. Those need a schedule model and a
  time-of-day notion this does not have; a half-built pager rotation is worse than none because people
  trust it.
- Per-sink rate limiting or digesting.
- Routing on subject/entity (see the decision below).

## Decisions

### First match wins, in declared order

The acceptance case — "CRITICAL routes to the pager only, INFO to the chat sink only" — is not
expressible with a union-of-all-matching-rules semantic: a `min: critical → pager` rule and a
`min: low → chat` rule both match a critical notification, so the critical page would also go to chat. A
firewall-style ordered table with first-match-wins expresses exclusivity directly and is a semantic
operators already know.

The cost is that rule order matters and a broad early rule shadows later ones. That is inherent to the
semantic, and it is legible: the table is short, ordered, and read top to bottom.

### Unmatched goes everywhere, and is counted

The alternative — drop, or route to a default sink — both fail the same way: a routing table with a gap
silently stops delivering the notifications that fit no rule, and those are disproportionately likely to
be the novel ones. So an unmatched notification goes to **every** sink and increments
`openshield_notify_unrouted_total`, which is the signal that the table has a hole. Same fail-open shape as
the watchdog (D17) and the exec gate: degrade toward doing more, and make the degradation visible.

### Severity is stamped in `emit`, not derived in `notify`

Routing needs a severity on every notification. `notify` must not learn the risk→bucket mapping — that
mapping lives in `controlplane.Severity` (SIEM-6) and a second copy is exactly the drift SOAR-5 refused
when it made the store and the inline engine share one matcher. So `emit` — the single funnel — stamps
`Severity` from the existing function when a producer left it unset, and `notify` only knows how to RANK
the labels. A test asserts each `controlplane.Severity*` constant ranks in `notify`, so the two
vocabularies cannot drift apart silently.

### Named sinks, backward compatibly

`OPENSHIELD_ALERT_WEBHOOK` entries become `name=url`; a bare URL is still accepted and auto-named
`sink-N`. With no `OPENSHIELD_ALERT_ROUTES` the Router is not installed at all and behaviour is exactly
today's `Multi`. Nothing about an existing deployment changes until an operator writes a table.

### Routing matches kind and severity only

Deliberately no subject/entity selector. A rule selecting on a subject would put a pseudonymous identifier
into a table an operator reads and edits — a re-identification surface (D23) and, worse, a way to route
one person's alerts somewhere nobody looks. The spec states it so a later contributor sees the omission
was a decision.

### The approval notification carries the subject, not the reason

`KindApprovalPending` carries the approval id and its subject kind/id — enough to find it. The requester's
free-text reason is not put into a field routing matches on: routing rules are matched against a closed
vocabulary, and matching on free text would make the routing decision depend on what a requester typed.

## Risks / Trade-offs

- **A shadowing rule silently captures traffic a later rule intended** → inherent to first-match-wins;
  mitigated by the table being ordered, short and load-validated, and by the unrouted counter catching the
  opposite failure.
- **Fail-open over-notifies during a misconfiguration** → deliberate and counted. The reverse failure is
  silent.
- **Approval notifications add volume** → they are deduped by the existing idempotency key like every
  other notification, so one request pages once.
- **Severity stamping changes existing notifications** → additive field only; a receiver that ignores it
  is unaffected.

## Migration Plan

No schema change. The feature is inert until `OPENSHIELD_ALERT_ROUTES` names a table; without it,
`SetNotifier` receives the same `Multi` it does today.

## Open Questions

- Whether an escalation ladder should be a routing concern or a playbook step (SOAR-4 already has the
  durable, resumable state a timed escalation would need) — deferred rather than guessed.
