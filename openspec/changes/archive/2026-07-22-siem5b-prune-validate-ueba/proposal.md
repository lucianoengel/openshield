## Why

The persisted peer-UEBA baseline grows without bound and trusts its own storage. `PersistBaselines`
UPSERTs every subject the analyzer has ever seen, forever — the `ueba_baselines` table and the
in-memory subject map both grow monotonically, and a long-decayed (effectively cold) subject is never
removed. And `loadBaselines`/`WithSnapshot` restore whatever the table holds VERBATIM, so a row with a
NaN/negative `count` or a future `last_seen` — reachable by anything with DB write access — corrupts
the baseline (NaN poisons every z-score; a future `last_seen` freezes/inflates decay).

## What Changes

- **Prune:** the analyzer drops subjects whose decayed activity has fallen below a small ε (they are
  cold), returning them so persistence can DELETE their rows — bounding both the map and the table.
- **Validate on load:** `loadBaselines` skips a row with a non-finite/negative `count` or a
  future `last_seen`; `WithSnapshot` skips a non-finite/negative `count` as a library-level guard — a
  corrupt baseline is dropped, never applied.
- **Batch in a transaction:** `PersistBaselines` runs the deletes + upserts in one transaction (atomic
  and faster than N autocommit statements).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `peer-ueba`: the analyzer can prune cold subjects, and restore rejects a corrupt (non-finite/
  negative-count) baseline entry rather than applying it.
- `control-plane`: baseline persistence prunes decayed rows, validates rows on load (skipping a
  non-finite/negative count or a future last-seen), and writes atomically in a transaction.

## Impact

- **Code:** `internal/analytics/peerueba/peerueba.go` (`Prune`, `PruneThreshold`, `WithSnapshot`
  validation), `internal/controlplane/controlplane.go` (`PersistBaselines` prune + txn,
  `loadBaselines` validation), and tests.
- **No proto/core change; no new migration** (no schema change).
- **Deferred (noted follow-up, not in this change):** persisting the `peerLastAlert` cooldown across
  restarts — benign (a subject may re-alert once after a restart); it needs a schema column and is
  tracked as a SIEM-5b remainder.
