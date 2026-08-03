# Tasks — PRIV-1 exclusion wiring

- [x] 1. `core.ParseTimeWindows` — `HH:MM-HH:MM` list, fail-loud on malformed, inverted, out-of-range
      and midnight-crossing windows.
- [x] 2. `Engine.SetExclusions` + `Engine.ProcessObserved` applying the exclusion before `Dispatch`;
      `Process` stays the non-excludable verdict entry.
- [x] 3. `Engine.Excluded` / `Engine.ExclusionsUnevaluable` counters, both read outside tests.
- [x] 4. Move the OBSERVATION producers onto `ProcessObserved`; leave the exec gate and the clipboard
      mediator on `Process`.
- [x] 5. `OPENSHIELD_EXCLUDE_PATHS` / `OPENSHIELD_EXCLUDE_WINDOWS` config entries + engine wiring,
      with a startup line naming what is on and what it cannot cover.
- [x] 6. Tests: an excluded path is never classified; a break-time event is never classified; a
      path-less event is observed AND counted; an enforcement verdict is never excluded; window
      parsing rejects each malformed shape.
- [x] 7. Mutation-verify each.
- [x] 8. Spec delta, DPIA template, README/roadmap.
