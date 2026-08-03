# Tasks — SEC-A configuration bounds and direction

- [x] 1. `Sensitivity` (NotSensitive / RaisingWeakens / LoweringWeakens / AnyChangeWeakens) and
      `ZeroDisables` on `Field`.
- [x] 2. `Field.Weakens(from, to)`, with a disabling value sorting to the weakest end.
- [x] 3. `atLeast` / `atMost` / `between` / `atLeastN` bound helpers whose messages name the consequence,
      and which never re-report a parse error.
- [x] 4. Bounds on CORRELATE_INTERVAL, OVERDUE_THRESHOLD, FLEET_RETENTION, RETENTION_INTERVAL,
      BEACON_MIN_CONTACTS; directions on all seventeen detection/retention fields.
- [x] 5. Migration 047: `config_changes.weakens`.
- [x] 6. `ApplySettings` computes it against the stored value or the DEFAULT, records it per change, and
      emits `KindConfigWeakened` after commit when any change weakened.
- [x] 7. `ConfigChange.Weakens` projected on the revision read path.
- [x] 8. Tests: the four named values are refused with a consequence; ordinary values still accepted;
      every default satisfies its own bound; direction is computable both ways; disabling sorts weakest;
      a bound never reports a parse error; the classified set is pinned.
- [x] 9. Tests: a weakening change pages someone naming the setting and author; a tightening change is
      silent; a mixed revision is judged per change.
- [x] 10. Mutation-verify all twelve.
- [x] 11. Spec delta + roadmap.
