## 1. The kind

- [x] 1.1 Add `KindSocketPath` to `internal/config`, documented with why it is distinct from
      `KindOutputPath` and why that reverses D321.
- [x] 1.2 Add the platform limit behind build tags: 108 on Linux, 104 elsewhere.
- [x] 1.3 Validate a socket path as an output path PLUS the length bound; the error names the field, the
      actual length and the limit.

## 2. Apply it

- [x] 2.1 Redeclare the four socket settings (`OPENSHIELD_EXEC_IPC_SOCKET` on both the agent and engine,
      `OPENSHIELD_PRINT_SOCKET` on both the engine and print filter) as `KindSocketPath`.
- [x] 2.2 Tighten the fitness guard: a setting whose key ends in `_SOCKET` must be `KindSocketPath`.

## 3. Prove it

- [x] 3.1 Tests: an over-long path is refused and the message carries the length; a path within the limit
      is accepted; a missing parent is still refused.
- [x] 3.2 Mutation: drop the length check → the over-long test FAILS. Mutation: validate against a
      portable 104 on Linux → a legitimate 106-byte path is refused → that test FAILS.
- [x] 3.3 `make quick`, then `OPENSHIELD_REQUIRE_POSTGRES=1 make all`.
- [x] 3.4 Commit with a D-number, archive WITH the spec sync, and CHECK CI.
