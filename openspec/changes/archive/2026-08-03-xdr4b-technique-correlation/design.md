# Design — XDR-4b technique-level correlation

## The load-bearing decision: evidence is derived, never declared

`internal/policy/mapping.go` computes `attack.IDs(attackSignals(st))` to build `input.attack.techniques`.
The Decision gets that **same slice**, from the same call, at the same moment.

The alternative — reading a `techniques` key out of the Rego result — was rejected. It is more
flexible and it is wrong. A policy module is operator-authored text composed from a default pack, zero
or more compliance packs and a custom module (ADR-5). If any of those could set the technique, then a
single careless `techniques := ["T1567.002"]` in a custom rule would make every event it matched claim
data exfiltration to cloud storage, and the technique-sequence hunt would return incidents built from
assertions rather than signals.

The rule is: **a technique is evidence, and evidence is derived.** Policy decides what to *do* about
signals; it does not get to decide what the signals *were*.

## Why ids and not names

`Technique{ID, Name}` is the internal shape. Only the id crosses the contract.

The name is presentation: MITRE renames techniques (T1086 "PowerShell" became a sub-technique of
T1059), and a name copied into a hash-chained audit ledger is frozen at the moment of writing and
cannot be corrected without breaking the chain. The id is the stable key; the name is looked up at
display time from the build's own table, which is where a rename can land.

## Contract validation, and the vocabulary that must not drift

`ValidateDecision` refuses a technique id outside the curated set. That set is derived from the same
`allTechniques` list the mapper emits from, so the two cannot disagree by construction — plus a test
that drives every signal shape the mapper can see through `Techniques()` and asserts each result is
`Known`. Without that test the failure mode is silent and one-directional: the mapper starts emitting
a technique, the validator refuses the decision, and the alert never reaches the stream at all. A
dropped alert looks exactly like a quiet network.

`ValidateDecision` is called on the projection path (`projectDecisionAlert`) *after* the alertable
check and before the decision is reasoned about — that ordering is already established and unchanged.

## The ragged-array trap

The correlation query aggregates each entity's alerts. `array_agg(techniques ORDER BY …)` over a
`TEXT[]` column would build a **two-dimensional** array, and Postgres requires those to be
rectangular. Measured against the real server, not assumed:

```
=> SELECT array_agg(t) FROM (VALUES (ARRAY['a','b']), (ARRAY['c'])) v(t);
ERROR:  cannot accumulate arrays of different dimensionality
```

So the moment one alert carries two techniques and another carries one, the query errors at runtime —
not at review time, and only on real data.

So the aggregation is `array_agg(array_to_string(techniques, ' ') …)`: a flat `TEXT[]`, one
space-joined string per alert, split back in Go. Technique ids contain no spaces (they are
`T####[.###]`), which is what makes the join unambiguous.

## Sequence semantics: two steps need two moments

`matchesTechniqueSequence` matches an ordered subsequence over the entity's alerts in detection
order, with one rule that is not obvious: **two steps may not be satisfied by the same alert.**

An alert can carry several techniques — a copy of a private key to a cloud-sync folder evidences both
`T1552` and `T1567.002` from one event. Set containment would call that a match for
`T1552 → T1567.002`. It is not one. The sequence is an ordering claim, and one alert is one moment;
it cannot evidence "then". This mirrors the reasoning already recorded for the domain sequence, where
accepting the reverse order was rejected as claiming something materially stronger than the data
supports.

The step index therefore advances on a **strictly increasing alert index**. The mutation that proves
this is load-bearing: allow a step to match the same alert as its predecessor, and a single
combined-signal alert satisfies a two-step hunt.

## Unknown technique in a query is a 400

Same rule as `knownDomain`: a `technique_sequence` step naming an id no producer can emit would
silently never match, and the operator would read an empty list as "nothing happened". It is refused,
loudly, with the id quoted (SEC-8).

## Contradiction check

None found. The archived `attack-mapping` spec states the mapping is a curated starter set over
signals OpenShield actually produces and that no technique is emitted without a real signal
evidencing it. Persisting the derivation strengthens that requirement rather than conflicting with
it: the technique on the Decision has, by construction, the same provenance as the technique in the
policy input.
