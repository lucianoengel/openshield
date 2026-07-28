# Tasks

- [x] 1. `cmd/openshield-dlp-index`: `buildEDM` calls `classify.BuildEDMIndex`, reports the skipped
      count on stderr, and fatals when nothing was indexed — matching `buildRecord`.
- [x] 2. Integration scenario: build an index from a file mixing a distinctive identifier with common
      words; the distinctive value is DETECTED and a document containing only the common word is NOT.
- [x] 3. Integration: a file of only non-distinctive values is REFUSED, naming the reason.
- [x] 4. Mutation-verify: restore the unfiltered loop → the common-word document is detected, failing
      the scenario.
- [x] 5. Targeted tests green; decision record; spec sync on archive.
