# Tasks

- [x] 1. `internal/agent/execmon`: extract the inotify record walk out of `WatchForNewExecutables` into
      a PURE function over a byte slice. No behaviour change; the `os.Stat`/`MarkFile` half stays put.
- [x] 2. Fuzz targets for the two kernel decoders — `execmon.decodeMeta` and `openmon.decodeMeta` —
      in-package, seeded structurally (exactly-`metaLen`, valid, `EventLen` of 0 / `metaLen-1` /
      `len(buf)` / `MaxUint32`, and two concatenated frames so the LOOP is exercised).
- [x] 3. A fuzz target for the extracted inotify walk. Its `name[]` is an attacker-created filename, so
      seed a record whose declared name length overruns the buffer and one whose name is unterminated.
- [x] 4. Fuzz targets for `openipc` and `execipc`: `ReadResponse` (the PRIVILEGED decoder) and
      `ReadRequest` (the engine's, and the only content-bearing frame in the system).
- [x] 5. Every target asserts PROGRESS — a successful decode returns a strictly shorter remainder — and
      that decoded lengths respect `MaxPathLen`/`MaxPrefixLen`. Not merely absence of panic.
- [x] 6. Verify the assertions can fail: mutate each decoder so it returns its input unchanged, and so
      it exceeds its declared bound, and observe the targets fail. A fuzz target that cannot fail is
      the emptiest green check there is.
- [x] 7. Run every target locally for a real budget — minutes, not the CI smoke budget — and record
      what was and was not found. Commit any crasher as a seed.
- [x] 8. CI: a bounded `-fuzztime` smoke pass in the existing `invariants` job, with the step name and
      the tasks both saying it is a SMOKE TEST and not a soak.
- [x] 9. Run `scripts/check-agent-deps.sh` and confirm the new test files did not pull a banned package
      into the agent's dependency graph — verified, not assumed.
- [x] 10. Correct the roadmap's framing of this item: the RCE justification is wrong for a memory-safe
      language, and the real one (crash/OOM/spin in a process answering blocking permission events) is
      what should be recorded.
- [x] 11. Targeted tests green; decision record stating the honest yield — including a null result if
      that is what it is; spec sync on archive.
