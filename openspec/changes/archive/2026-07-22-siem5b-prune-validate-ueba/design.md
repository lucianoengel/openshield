## Context

The analyzer keeps a `map[subject]*entry{count,last}`; `ContextFor` decays `count` forward from `last`
at query time. `PersistBaselines` snapshots the whole map and UPSERTs each row (N autocommit
statements); `loadBaselines` SELECTs them and `WithSnapshot` restores `{count,last}` verbatim. Nothing
removes a decayed subject, and nothing validates a restored row — a NaN count (poisons z-scores) or a
future `last_seen` (decay guard returns the count undecayed → frozen/inflated) survives restore, and
both the table and map grow forever.

## Goals / Non-Goals

**Goals:**
- Bound the subject map and the `ueba_baselines` table by pruning cold (decayed-below-ε) subjects.
- Reject a corrupt baseline row on load (non-finite/negative count, future last-seen).
- Persist atomically in one transaction.

**Non-Goals:**
- Persisting the `peerLastAlert` cooldown (a benign one-time re-alert after restart; a schema change,
  deferred as a SIEM-5b remainder).
- Changing the decay math, the z-score, or the restore-exactness property (SIEM-5/D168).

## Decisions

### D-a · `Analyzer.Prune(minCount)` removes cold subjects, returns their ids
Under the lock, for each subject compute `decayedAt(now)`; if `< minCount` delete it and collect its
id. `PruneThreshold = 0.01` (an activity decayed below a hundredth of a unit is indistinguishable from
cold; a returning subject simply re-accrues from zero, exactly as a never-seen one). Returning the ids
lets persistence delete the corresponding rows so the table shrinks with the map.

*Alternative considered:* a TTL on `last` (drop subjects not seen in N half-lives). **Rejected** —
decayed-count is the same signal the analyzer already uses and needs no second knob; a burst that
decayed below ε is cold regardless of wall-clock age.

### D-b · Validate on load, at both layers
`loadBaselines` (the DB boundary, has the server clock) skips a row whose `count` is NaN/±Inf or `< 0`,
or whose `last_seen` is after `now + 1m` (clock-skew grace) — the future-time case that only the DB
layer can judge. `WithSnapshot` (library) independently skips a NaN/±Inf/negative count, so a corrupt
snapshot from any caller is refused even without the server's validation. Defense in depth; a skipped
subject is simply cold.

### D-c · Persist in one transaction
`PersistBaselines` prunes first (so the snapshot excludes cold subjects), then in a single
`Begin`/`Commit` transaction DELETEs the pruned ids and UPSERTs the survivors. Atomic (a crash
mid-persist leaves the prior consistent state) and fewer round-trips than N autocommits. Still a no-op
when peer-UEBA is disabled, still best-effort at the call site.

## Risks / Trade-offs

- **Pruning a subject that returns** → it re-accrues from zero, identical to a first-time subject; the
  ε is far below any alerting level, so no anomaly is lost.
- **A future `last_seen` from legitimate clock skew** → the 1-minute grace absorbs normal skew; a
  row beyond it is treated as corrupt (skipped), which is the safe choice against a DB-write attacker.
- **Transaction contention** → the persist runs on a periodic loop / shutdown, off the ingest path;
  one short transaction per interval is negligible.

## Open Questions

None. The `peerLastAlert` persistence remainder is deferred, not open.
