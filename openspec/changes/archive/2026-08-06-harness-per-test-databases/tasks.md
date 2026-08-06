# Tasks — per-test databases

- [x] 1. Scope the database name to `t.Name()` in `DSNFor`.
- [x] 2. Truncate from the tail, keeping the caller's label, within 63 bytes.
- [x] 3. Unit assertions on the naming; mutate the naming and the wiring separately.
- [x] 4. Verify with a suite slice covering every `DSNFor` caller, run together.
