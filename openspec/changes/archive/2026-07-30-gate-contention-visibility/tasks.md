# Tasks

- [x] Wire the gate's discard counters into `reportDiscards` (audit rows, unclassified, suppressor).
- [x] `OPENSHIELD_GATE_ASYNC_QUEUE` so the overflow is reachable; `OPENSHIELD_DISCARD_REPORT_INTERVAL`
  for the listeners too.
- [x] Integration case: a burst of distinct paths against a queue of one; the engine reports WHILE running.
- [x] Assert every open still gets a verdict under load — depth is lost, the decision is not.
- [x] Mutation: shutdown-only reporting must fail the scenario.
- [x] `make quick` green; targeted package + integration tests only.
