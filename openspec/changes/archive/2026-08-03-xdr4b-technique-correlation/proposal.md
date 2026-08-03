# XDR-4b · Technique-level correlation

## Why

XDR-4 shipped cross-domain correlation with a named, honest residual:

> the sequence vocabulary is **domains, not ATT&CK techniques** — techniques are Rego policy INPUT
> and are never persisted on an alert, so technique-level sequences need a `Decision` contract
> change. Named, not faked.

That residual is the gap between what OpenShield *computes* and what an operator can *ask*. SIEM-7
already derives MITRE ATT&CK technique ids from the platform's own content-free signals — credential
detector types, threat-intel categories, the exfil channel, the behavioural findings — and feeds them
to Rego as `input.attack.techniques`. A policy can route on a technique. But the moment the Decision
is produced, the derivation is discarded: nothing downstream ever sees it again.

So the correlation lane speaks in `dlp → hips → nips`, which is a statement about *which detection
plane fired*, not about *what the adversary did*. Every SOC in the world writes its hunt as
`T1552 → T1218 → T1567.002`. A domain sequence cannot express that, and worse, the four coarse domain
labels collapse genuinely different behaviours: "hips then nips" is satisfied equally by a LOLBin
followed by a DNS tunnel and by a deleted file followed by an SMTP send.

## What changes

1. **`Decision.techniques`** — an additive repeated-string field carrying the technique ids the
   decision's evidence supported. Ids only: the *name* is a display lookup that would rot inside a
   hash-chained ledger.

2. **The derivation writes it; the policy never does.** The evaluator attaches the ids produced by
   the same `attack.IDs(attackSignals(state))` call that built the Rego input. A technique is
   deliberately **not** read back out of the policy result. Policy is operator-authored text; if a
   rule could *declare* a technique, then "what did this asset evidence?" would be answered by
   whatever the rules asserted rather than by what the signals showed — and the correlation lane
   would be correlating claims instead of evidence.

3. **The contract refuses an unknown technique id.** `ValidateDecision` already refuses an
   out-of-range confidence for exactly this reason: an enrolled-but-compromised agent must not be
   able to inject arbitrary strings into a widely-read derived table. Technique ids get the same
   treatment, checked against the curated vocabulary the mapper can actually emit.

4. **`unified_alerts.techniques`** — the projection persists them, so correlation reads what the
   endpoint evidenced rather than re-deriving it from an event it does not have.

5. **`technique_sequence`** — the cross-domain rule accepts an ordered technique subsequence
   alongside (not instead of) the domain sequence, fail-loud on an id no producer can emit, and each
   incident reports the distinct techniques it saw in first-seen order.

## Impact

- **Contract:** additive proto field at a designed growth point (D69/D101). No migration of existing
  Decisions; an absent field is an empty list, which is exactly "no signal mapped to a technique".
- **Schema:** one additive nullable column on `unified_alerts`.
- **Behaviour:** nothing changes for a caller that does not pass `technique_sequence`. Domain
  sequences keep working unchanged.
- **Deliberately not in scope:** technique-level *severity* weighting (a technique is not a risk
  score); sub-technique rollup (`T1567.002` does not imply `T1567` — the mapper emits exactly what it
  derived and inventing the parent would be a claim the evidence does not make); backfill of alerts
  that predate the column.
