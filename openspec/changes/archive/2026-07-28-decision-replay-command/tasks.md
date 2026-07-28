# Tasks

- [x] 1. `internal/cli`: add `Replay(ctx, w, r Reader, dispatcher, event)` — look up the recorded
      entry by event id, refuse zero or multiple matches distinctly, re-dispatch, compare via
      `core.DecisionsEquivalent`, and report REPRODUCED / DIVERGED / UNAVAILABLE with distinct exit
      codes.
- [x] 2. `cmd/openshieldctl`: add the `replay` subcommand reading an event from a file, composing the
      same default+packs policy the engine does.
- [x] 3. The divergence report names the differing field AND states that the input may have changed.
- [x] 4. Unit tests in `internal/cli`: reproduced, diverged, no-entry, and ambiguous-id, each with a
      distinct exit code.
- [x] 5. Integration scenario: a real decision written to the ledger by the engine, replayed and
      reproduced; then replayed against a policy that decides differently and reported as diverged.
- [x] 6. Mutation-verify: make the comparison ignore `action` → the diverged case reports reproduced.
- [x] 7. Targeted tests green; decision record; spec sync on archive.
