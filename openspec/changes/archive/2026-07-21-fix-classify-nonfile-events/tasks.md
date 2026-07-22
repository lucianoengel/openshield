# Tasks — fix classify on non-file events

- [x] Regression test: a DNS network event flows through real `eng.Process` to a Decision + audit (fails pre-fix).
- [x] `classifyStage`: skip (empty classification, no worker call) when the event has no filesystem target.
- [x] Keep the empty-path error for a genuine file event; add a test pinning it.
- [x] Mutation: content-free skip broadened to swallow file events → the pathless-file test fails.
- [x] `make all` clean.
- [x] docs/decisions.md D134; sync spec; archive; commit; push; memory.
