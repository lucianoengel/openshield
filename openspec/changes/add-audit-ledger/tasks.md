## 1. Schema and migrations

- [ ] 1.1 Forward-only migration runner; versioned, applied in order, recorded in a
      `schema_migrations` table
- [ ] 1.2 Initial migration: entries table with decision payload, chain hash, previous hash,
      signature, sequence, and the columns later phases need — retention class, purpose,
      pseudonymous subject, `context_version`
- [ ] 1.3 **Test**: the initial migration creates every required column. A migration omitting
      one must fail here rather than deferring the cost to a chain break

## 2. Hash chain

- [ ] 2.1 Entry hashing over a canonical serialization (field order must be stable, or the same
      entry hashes differently on different runs)
- [ ] 2.2 `Append` links each entry to its predecessor; genesis value recorded explicitly
- [ ] 2.3 **Attack test**: edit an entry in place → verification fails and names the first
      broken entry
- [ ] 2.4 **Attack test**: delete a middle entry → verification fails at the following entry
- [ ] 2.5 **Attack test**: reorder two entries → verification fails

## 3. Forward integrity

- [ ] 3.1 Key ratchet `K_{n+1} = H(K_n)`; sign each entry with the current key; overwrite the
      prior key after use
- [ ] 3.2 **Attack test**: given the key in force at entry N, attempt to forge a valid signature
      for an entry before N. Must fail. This is the test that proves forward integrity rather
      than assuming it
- [ ] 3.3 Document honestly in code that key destruction in Go is best-effort — the GC may
      retain copies. State the residual risk rather than implying erasure

## 4. Verification

- [ ] 4.1 `Verify` returns a structured result: validated range, first break index, anchor state
- [ ] 4.2 **Test**: a consistent chain with no anchor reports completeness as UNVERIFIED, not as
      success. A bare boolean would let a caller report a guarantee nobody has
- [ ] 4.3 **Test**: a truncated chain reports absence rather than success

## 5. Wiring

- [ ] 5.1 `core.Ledger` interface; `internal/store/postgres` implements it
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
