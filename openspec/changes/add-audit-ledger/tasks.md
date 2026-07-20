## 1. Schema and migrations

- [x] 1.1 Forward-only migration runner; versioned, applied in order, recorded in a
      `schema_migrations` table
- [x] 1.2 Initial migration: entries table with decision payload, chain hash, previous hash,
      signature, sequence, and the columns later phases need — retention class, purpose,
      pseudonymous subject, `context_version`
- [ ] 1.3 **Test**: the initial migration creates every required column. A migration omitting
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

- [x] 3.1 Key ratchet `K_{n+1} = H(K_n)`; sign each entry with the current key; overwrite the
      prior key after use
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
- [ ] 5.2 Extend `scripts/check-core-deps.sh` so `internal/core` cannot import a database driver;
      verify by adding the import and observing the failure
- [ ] 5.3 Dispatcher `OnOutcome` appends to the ledger; a failed append returns an error and is
      never swallowed. **Test**: unreachable database surfaces an error at the caller
- [ ] 5.4 Integration test against a real Postgres via Podman, skipped when unavailable — and
      the skip must be LOUD, since an always-skipped test that shows green is worse than none

## 6. Docs

- [ ] 6.1 Record in `docs/decisions.md`: chain plus key evolution, and why neither alone suffices
- [ ] 6.2 State the deployment constraint plainly — the agent needs a reachable database to
      record anything, unresolved until T-024
- [ ] 6.3 Mark T-026 and T-009 done; sync specs; archive

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
