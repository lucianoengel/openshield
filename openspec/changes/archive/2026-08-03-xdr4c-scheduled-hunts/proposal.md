# XDR-4c · The narrative rule runs on the clock

## Why

XDR-4's ordered-sequence rule — the half of cross-domain correlation that makes an *attack narrative*
claim rather than a breadth claim — has never been reachable by the thing that raises incidents.

`CrossDomainRule.Sequence` (and, since XDR-4b, `TechniqueSequence`) is written in exactly one place in
the tree outside tests: the `GET /incidents` query-parameter parser. The scheduled correlation loop —
SOAR-2's leader-only clock, the mechanism whose entire justification is *"an incident existed only if a
human happened to look… detection has to run on a clock"* — constructs:

```go
controlplane.CrossDomainRule{
    Window:           window,
    MinDomains:       cfg.Int("OPENSHIELD_CORRELATE_MIN_DOMAINS"),
    RecurrenceWindow: recur,
}
```

`Sequence`, `TechniqueSequence` and `MinSeverity` are left at their zero values, and always have been.

So the platform can *answer* "did T1552 then T1567.002 happen on this asset?" — to an operator who
already suspected it and typed the query. It can never *tell* anyone. No sequence match has ever raised
an incident, paged a human, opened a case, or started an escalation ladder. XDR-4's own design note says
"an attack narrative is an ordering claim: identity-anomaly THEN exec THEN DNS is a story" — and the
story has only ever been readable by someone who already knew the ending.

This is the same defect shape as D313: a capability whose producer exists, whose tests pass, and whose
only caller is an interactive request.

## What changes

1. **Named hunts, configured and run on the correlation tick.** `OPENSHIELD_CORRELATION_HUNTS` points
   at a JSON file of named rules — each a domain sequence, a technique sequence, or both, with its own
   window, domain minimum and severity floor. The loop materializes the breadth rule as it does today,
   *and* every configured hunt, on the same tick. Following `OPENSHIELD_ESCALATION_LADDER`'s precedent:
   a `KindPath`, re-read per tick so editing hunts needs no restart, and a file that fails to parse
   leaves hunts OFF loudly rather than substituting a guess.

2. **A hunt file is validated against the real vocabularies at load.** An unknown domain or an
   underivable technique is refused with the offending value named — the same rule the HTTP handler
   already applies, for the same reason: a step nothing can emit would never match, and silence would
   read as "that attack chain did not happen".

3. **`incidents.rule_name`, and the unique indexes reshaped around it.** This is mandatory, not
   cosmetic — and migration 028 already wrote the argument for the level above:

   > Left as-is, a burst incident and a cross-domain incident for the same asset would collide and the
   > second upsert would silently overwrite the first — an operator would lose an incident with no
   > trace.

   Exactly that, one level down: two hunts matching one entity share `kind='cross_domain'`, so today
   they would collide on `incidents_open_entity_idx`. The second upsert takes the `DO UPDATE` path,
   overwriting the first hunt's alert count, domain count and domain list — and because only a genuine
   INSERT pages (SOAR-1/D220), **the second hunt never pages at all**. Every tick the row would
   flip-flop between whichever hunts matched.

4. **The page names the hunt.** "3 alerts across 2 domains (dlp, hips)" does not tell an operator that
   `credential-staged-then-exfiltrated` fired. Naming the rule *is* the narrative claim; without it a
   sequence incident is indistinguishable from a breadth incident.

## Impact

- **Schema:** one additive column, two index reshapes. Existing rows get `rule_name = ''`, which is
  precisely what they are: the unnamed breadth rule.
- **Behaviour:** with no hunt file configured, nothing changes — the loop runs the breadth rule exactly
  as before, and `GET /incidents` is untouched.
- **Deliberately not in scope:** hunts over the burst rule (it has no sequence concept); per-hunt
  notification routing (SOAR-9 routes by kind and severity, and a hunt is neither); a hunt-authoring UI;
  retro-correlation of alerts predating a newly added hunt.
