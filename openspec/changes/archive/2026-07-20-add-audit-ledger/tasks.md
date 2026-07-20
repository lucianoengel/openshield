## 1. Schema and migrations

- [x] 1.1 Forward-only migration runner; versioned, applied in order, recorded in a
      `schema_migrations` table
- [x] 1.2 Initial migration: entries table with decision payload, chain hash, previous hash,
      signature, sequence, and the columns later phases need — retention class, purpose,
      pseudonymous subject, `context_version`
- [x] 1.3 **Test**: the initial migration creates every required column. A migration omitting
      one must fail here rather than deferring the cost to a chain break

## 2. Hash chain

- [x] 2.1 Entry hashing over a canonical serialization (field order must be stable, or the same
      entry hashes differently on different runs)
- [x] 2.2 `Append` links each entry to its predecessor; genesis value recorded explicitly
- [x] 2.3 **Attack test**: edit an entry in place → verification fails and names the first
      broken entry
- [x] 2.4 **Attack test**: delete a middle entry → verification fails at the following entry
- [x] 2.5 **Attack test**: reorder two entries → verification fails

## 3. Forward integrity

- [x] 3.1 ~~Key ratchet `K_{n+1} = H(K_n)`~~ — **superseded.** A symmetric ratchet cannot be
      verified without the seed, and the seed forges; see `docs/decisions.md` D30. Implemented
      instead as an evolving Ed25519 keypair: sign with the current key, publish the successor
      public key signed by its predecessor, destroy the predecessor's private key
- [x] 3.2 **Attack test**: given the key in force at entry N, attempt to forge a valid signature
      for an entry before N. Must fail. This is the test that proves forward integrity rather
      than assuming it
- [x] 3.3 Document honestly in code that key destruction in Go is best-effort — the GC may
      retain copies. State the residual risk rather than implying erasure

## 4. Verification

- [x] 4.1 `Verify` returns a structured result: validated range, first break index, anchor state
- [x] 4.2 **Test**: a consistent chain with no anchor reports completeness as UNVERIFIED, not as
      success. A bare boolean would let a caller report a guarantee nobody has
- [x] 4.3 **Test**: a truncated chain reports absence rather than success

## 5. Wiring

- [x] 5.1 `core.Ledger` interface; `internal/store/postgres` implements it
- [x] 5.2 Extend `scripts/check-core-deps.sh` so `internal/core` cannot import a database driver;
      verify by adding the import and observing the failure
- [x] 5.3 Dispatcher `OnOutcome` appends to the ledger; a failed append returns an error and is
      never swallowed. **Test**: unreachable database surfaces an error at the caller
- [x] 5.4 Integration test against a real Postgres via Podman, skipped when unavailable — and
      the skip must be LOUD, since an always-skipped test that shows green is worse than none

## 6. Docs

- [x] 6.1 Record in `docs/decisions.md`: chain plus key evolution, and why neither alone suffices
- [x] 6.2 State the deployment constraint plainly — the agent needs a reachable database to
      record anything, unresolved until T-024
- [x] 6.3 Mark T-026 and T-009 done; sync specs; archive

## Verification performed (crypto)

Every guard mutation-tested. Two mutations were SILENT on the first pass and
that exposed a real gap rather than redundancy:

| mutation | caught by |
|---|---|
| prev-hash link not checked | `TestDeletedEntryIsDetected`, `TestReorderedEntriesAreDetected` |
| entry signature not checked | `TestValidHashWithInvalidSignatureIsRejected` — **added after this mutation was silent** |
| key chain not checked against anchor | `TestKeyChainMustStartAtTheAnchor` |
| ratchet/seed retained (original bug) | design reversed; symmetric API deleted |
| epoch removed from hash | **nothing** — genuine redundancy, see below |

**The signature gap.** Removing the signature check initially broke no test,
because every "forgery" in the suite also corrupted the entry hash. The hash is
unkeyed and computed over public content, so a real attacker recomputes it
freely — the signature is the only thing stopping them, and nothing tested it.
`TestValidHashWithInvalidSignatureIsRejected` now leaves hash and prev-link
intact and corrupts only the signature.

**The epoch-in-hash redundancy, stated honestly.** Removing the epoch from the
canonical encoding breaks no test, and this one is not a gap: re-pointing an
entry to another epoch fails the signature check, and an attacker who *can*
sign for the claimed epoch still breaks the forward chain link at the next
entry. It is kept as defence in depth and is not independently testable.

## What the integration tests found

All three were invisible to the entire in-memory suite, which passed throughout.
Recorded because the lesson is about the *shape* of the gap, not the individual
bugs: every guard here was tested against an adversary, and none was tested
against the storage layer or against the passage of time.

**1. The chain was broken by its own database.** PostgreSQL `TIMESTAMPTZ` stores
microseconds; the canonical encoding commits to nanoseconds. Every entry sealed
with a real `time.Now()` verified as TAMPERED the moment it was read back. The
in-memory tests never saw it because they never round-tripped through Postgres,
and the first integration fixture accidentally hid it by truncating timestamps
itself — that truncation is now removed, so the test exercises the real path.
Fixed by sealing over the timestamp that will actually be stored, in the store,
because the precision limit belongs to the database and core may not import one.

**2. `key_epoch` was hashed but had no column.** It read back as 0, so every
entry past the first epoch boundary failed verification. This is precisely the
class of omission task 1.3 exists to catch — and 1.3's own required-column list
missed it on the first pass. It stayed latent because nothing called `Evolve()`:
with a single epoch, the missing column always read back correctly.

**3. Which exposed the larger one: nothing rotated the key at all.** `Evolve()`
had no production caller, so in a deployed system the epoch would never advance
and the key signing entry 0 would still be resident at entry 10,000 — forward
integrity of zero, from an implementation that verified perfectly. The spec
requirement "the compromise window is the epoch" was unbacked by any mechanism.
`Ledger.EpochEntries` now rotates on a bounded count, defaults finite rather
than "never", and is documented as a security parameter at the configuration
surface. `TestKeyEvolvesDuringAppendsAndTheChainStillVerifies` fails if rotation
stops or if the chain cannot verify across an epoch boundary.

## Verification performed (wiring)

| mutation | caught by |
|---|---|
| `report()` swallows the append error | `TestUnreachableLedgerSurfacesAtTheCaller`, `TestTimeoutIsRecordedAndItsFailureSurfaces` |
| `retention_class` dropped from migration 001 | `TestInitialMigrationCreatesEveryRequiredColumn` |
| timestamp truncation removed | 6 integration tests |
| pgx imported into `internal/core` | `scripts/check-core-deps.sh` (exit 1, verified by adding the import) |

The Postgres skip is loud on stderr regardless of `-v`, and CI sets
`OPENSHIELD_REQUIRE_POSTGRES=1` so a skipped suite fails rather than showing
green. An integration suite that skips silently manufactures confidence.
