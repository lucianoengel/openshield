# Tasks

- [x] 1. `internal/release`: add `LoadAndVerifyWithKey(dir string, pub ed25519.PublicKey)` — the pinned
      path — and express the existing `LoadAndVerify` in terms of it, so there is exactly one
      verification body and the pinned path cannot drift from the unpinned one.
- [x] 2. `internal/release`: add `Fingerprint(pub ed25519.PublicKey) string` (first 16 hex of the
      key's SHA-256).
- [x] 3. `cmd/openshieldctl`: add `--key` to `verify-release`; read and length-check the pinned key,
      failing hard on any problem with it and never falling back to the shipped key.
- [x] 4. `cmd/openshieldctl`: on the unpinned path, print to stderr what was and was not established,
      and how to pin. Exit status unchanged.
- [x] 5. `cmd/openshieldctl`: report the key fingerprint on success, both paths.
- [x] 6. Unit tests in `internal/release`: pinned verify accepts the right key, refuses a re-signed
      release, and a wrong-length key is an error rather than a fallback.
- [x] 7. Rewrite `TestVerificationWithoutAPinnedKeyIsIntegrityOnly` into the pinned scenarios: the
      re-signed release passes UNPINNED (the limit, still true) and is REFUSED when pinned.
- [x] 8. Mutation-verify: make the pinned path fall back to the shipped key on mismatch and confirm
      the re-signed release is accepted again.
- [x] 9. `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; decision record; roadmap/spec sync.
