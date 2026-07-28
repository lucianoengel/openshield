## 1. Choose the mark from the semantics

- [x] 1.1 `execmon.Open` takes the intended mark mode; per-file marking walks the monitored directories
      and marks each executable, mount marking behaves exactly as today.
- [x] 1.2 `cmd/openshield-agent` selects per-file ONLY when an allowlist is the sole configured signal.
- [x] 1.3 The startup line states which mark is in use and why, so the trade-off is visible.

## 2. Close the new-file hole

- [x] 2.1 An inotify watch over the monitored directories marks a binary on create, move-in and
      close-after-write.
- [x] 2.2 A directory created after startup is watched too.

## 3. Prove it

- [x] 3.1 Unit: mark-mode selection from each signal combination.
- [x] 3.2 VM: an allowlisted binary runs, an unlisted one is refused, and a binary CREATED AFTER the
      agent started is refused — the bypass assertion.
- [x] 3.3 Evidenced by the mark probe rather than an agent-side counter: on kernel 6.8 a per-file
      mark delivers ONLY for the marked file (`direct-child=true nested=false OUTSIDE=false`), so an
      execution elsewhere raises no event at all. Recorded as a test that prints its measurement.
- [x] 3.4 Mutation: skip the inotify re-mark -> the newly-created binary runs -> FAILS.

## 4. Land

- [x] 4.1 `make quick`, package tests, and the VM scenarios.
- [x] 4.2 Record in `docs/unwired-audit.md`.
- [x] 4.3 Commit with a D-number, archive WITH the spec sync, check CI.
