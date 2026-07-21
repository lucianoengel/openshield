# Tasks — persist the signed-telemetry sequence

## 1. Sequence store

- [x] 1.1 `internal/transport/nats`: a file-backed reservation `SeqStore` — `Load()` reads the persisted high-water (0 if absent; loud error if corrupt); `Reserve(hw)` persists a new high-water atomically (temp+rename, 0600).
- [x] 1.2 `SignedPublisher` takes an optional store; on construct it loads the high-water and starts the counter there; `publish` reserves a new block (hw += N) when the counter crosses the current high-water. Backward-compatible `NewSignedPublisher` stays in-memory; add `NewSignedPublisherWithSeq(...)`.

## 2. Wire + doc honesty

- [x] 2.1 `cmd/openshield-fleet-agent`: use a file-backed store at `OPENSHIELD_SEQ_FILE` (in-memory when unset).
- [x] 2.2 Reword `internal/transport/nats/nats.go`'s package comment: core NATS / at-most-once, not JetStream; name the offline queue as the durability path.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: a publisher emits sequences to a file, is discarded and RECREATED from the same file, and its next sequence is strictly greater than any used before (monotonic, no reuse across restart).
- [x] 3.2 **Test**: a corrupt seq file fails loudly (the publisher refuses to start), not a silent reset to 0.
- [x] 3.3 **Test (integration)**: an enrolled agent publishes, "restarts" (new publisher from the same seq file), publishes again — `VerifySigned` ACCEPTS the post-restart message (gap at most), never `ErrReplay`.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D66: the signed sequence is persisted (reservation-based, atomic like D46) so a restart is forward-monotonic, not a false replay; the transport doc corrected from JetStream to core NATS; durability across an outage is the offline queue (#4b).
- [x] 4.2 `openspec validate persist-telemetry-seq --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| publisher ignores the loaded high-water (resets to 0) | `TestSignedSeqMonotonicAcrossRestart`, `TestRestartedAgentNotReplayed` |
| corrupt seq file silently returns 0 (silent reset) | `TestSeqStoreCorruptFailsLoud` |

M1 reproduces the EXACT original bug (reset-to-0 on restart): the integration test
then shows the post-restart message rejected as a replay — proving the guard
catches the regression, not just a tautology. The signed sequence is now
persisted (reservation-based, atomic temp+rename like D46): a restart resumes
forward-monotonically and its telemetry is accepted (a gap at worst, D50), never a
replay. The transport doc no longer overclaims JetStream.
