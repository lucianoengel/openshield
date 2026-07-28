## Context

Found by asking a question the existing guard declines. `TestEveryEnvReadIsDeclared` checks that a read in
a command's own code is declared, and its comment explains why it does NOT check the reverse: a binary's
configuration surface includes what its libraries read (`OPENSHIELD_POLICY_PACK` in `internal/policy`,
`OPENSHIELD_JETSTREAM` in `internal/transport/nats`), so a command-scoped reverse check would flag both as
dead, and a module-scoped one "would mark every variable as read by every binary, which proves nothing".

That reasoning is right about the per-binary question and does not settle the different one: **is this key
read AT ALL, anywhere?** Module-scoped, that has a definite answer, and it is exactly the dead-setting
question. Two of 170 fail it.

## Decisions

### Strip comments, because the comment IS the symptom

`OPENSHIELD_POSTURE_PUBKEY` appears in `cmd/openshield-gateway/main.go` — in a comment explaining that
the gateway no longer reads it. A naive text search therefore finds it and concludes it is alive. The
prose that documents a retirement is the strongest signal a setting is dead, so the check must not treat
it as a reader.

### Read the setting rather than delete it — and the difference between the two cases is the point

The two dead settings get opposite treatments, and the check cannot tell you which. It reports that a
setting has no reader; whether the fix is to add one or to remove the setting depends on whether the
behaviour is wanted, which is a judgement.

`OPENSHIELD_NOTIFY_DEDUPE_RETENTION` names behaviour that is wanted and already implemented — the prune
runs, on a hardcoded 24-hour cutoff. So the setting is right and the READ is missing. **A first pass at
this change asserted the prune had no caller at all; it does, and the claim was wrong.** What is actually
wrong is narrower and nastier: the loop records a compliance event whose policy string is the literal
`OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h`, so the audit trail cites a setting the code never consulted. An
operator who set 7d has a record naming their knob and asserting someone else's value.

`OPENSHIELD_POSTURE_PUBKEY` names a mechanism SEC-12 deliberately replaced — one fleet-wide key any agent
could use to forge another's posture — so the setting is wrong and removing it is the fix. Wiring it
would resurrect the vulnerability that motivated the replacement.

Treating "no reader" as if it implied a single remedy would have produced exactly the wrong change in one
of the two cases.

### Prune to several windows, not one

An id only needs to outlive its dedupe window for page-once to hold. Pruning to exactly the window would
create a narrow band where an id is deleted just before its alert recurs, re-paging it — trading
unbounded growth for a rare duplicate page. The configured retention defaults far above the 10-minute
window, and the loop uses it as given.

## Risks / Trade-offs

- **The guard could become a nuisance** if a legitimately-unread setting is added deliberately (a
  placeholder for a feature landing next week). That is the right thing to block: an operator-visible
  field that does nothing is the defect, whatever the intention behind it.
- **Pruning changes what the dedupe ledger remembers.** Bounded by making the retention the operator's
  declared value rather than a constant chosen here.
