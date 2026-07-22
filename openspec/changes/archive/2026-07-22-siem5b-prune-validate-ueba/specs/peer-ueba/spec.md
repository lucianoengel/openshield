## ADDED Requirements

### Requirement: The analyzer prunes cold subjects and rejects a corrupt restored baseline

The analyzer MUST be able to prune subjects whose decayed activity has fallen below a small threshold
(they are indistinguishable from cold), reporting which subjects were removed, so a caller can bound
both the in-memory subject set and any persisted copy — a subject that returns simply re-accrues from
zero, exactly like a never-seen one, and no alert-level signal is lost. When restoring a persisted
baseline, the analyzer MUST reject an entry whose activity count is not a finite non-negative number
(NaN, infinity, or negative), applying only the well-formed entries — a corrupt stored value MUST NOT
poison the baseline.

#### Scenario: A decayed-below-threshold subject is pruned and a corrupt entry is not restored
- **WHEN** the analyzer prunes with a threshold above a long-decayed subject's current activity, and separately restores a snapshot containing a NaN or negative count alongside a valid entry
- **THEN** the decayed subject is removed and reported, while restore applies the valid entry and drops the non-finite/negative one
