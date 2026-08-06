# Tasks — CONSOLE-6

- [x] 1. Opaque position-only cursor: encode/decode `(received_at, id)`, refuse malformed.
- [x] 2. `EventFilter.Cursor`; keyset predicate `(received_at, id) < (…)` alongside existing filters.
- [x] 3. Over-read one row to derive `has_more`; discard it so `limit` means what it says.
- [x] 4. `next_cursor` absent on the last page, never empty.
- [x] 5. `/events` response shape carries rows + `has_more` + `next_cursor`; authority re-derived per page.
- [x] 6. Tests + mutations: truncation reports it; cursor carries no authority; malformed refused; the
      over-read row is not returned; paging reaches rows past the cap without repeats.
- [x] 7. Integration test against the shipped binary.
- [x] 8. Docs: decision row, roadmap status.
