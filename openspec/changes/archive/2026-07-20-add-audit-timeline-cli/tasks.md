## 1. Persist the public-key chain

- [x] 1.1 Migration `002`: `key_epochs` table (`index` PK, `public_key` BYTEA NOT NULL,
      `sig_by_prev` BYTEA null for anchor); foreign key `audit_entries.key_epoch` →
      `key_epochs.index`. Forward-only, same runner as 001
- [x] 1.2 **Test**: migration 002 creates `key_epochs` with exactly those columns and no
      private-key column. `TestKeyEpochsTableStoresOnlyPublicMaterial` — asserts the column set
      and fails the build if a private column is added
- [x] 1.3 Insert epoch 0 on first open of an empty database; carry the chain forward on resume by
      loading `key_epochs` rather than trusting a live signer
- [x] 1.4 Make `Append` transactional: begin, insert the new epoch row when this append evolved
      the key, insert the entry, commit. Preserve evolve-after-store ordering
- [x] 1.5 **Test**: an append that evolves the key writes the epoch row in the same transaction;
      a forced FK violation (entry referencing an absent epoch) fails at write.
      `TestEntryCannotReferenceUnstoredEpoch`

## 2. Verify from stored material, pinned to an anchor

- [x] 2.1 Load `[]core.KeyEpoch` from `key_epochs` in `Verify`; stop calling `signer.Chain()` /
      `signer.AnchorKey()` on the write path's signer
- [x] 2.2 Change `core.Ledger.Verify` to `Verify(ctx, expectedAnchor ed25519.PublicKey)`. Non-nil:
      fail if the stored chain does not start there. Nil: internal consistency, completeness
      forced UNVERIFIED with a reason naming the absent anchor
- [x] 2.3 **Test**: a verifier holding no `*Signer` verifies an untampered ledger, and a wrong
      anchor is rejected without falling back to the stored one.
      `TestVerifyFromStoredChainWithoutSigner`, `TestWrongAnchorIsRejected`
- [x] 2.4 **Test**: write, drop the ledger, reopen with a DIFFERENT signer instance, verify the
      pre-restart entries still pass. `TestChainSurvivesRestartWithFreshSigner` — replaces the
      old same-signer restart test, which hid the orphaning
- [x] 2.5 Update the one existing `Verify` caller to pass nil; confirm its behaviour is unchanged

## 3. The CLI

- [x] 3.1 `openshieldctl` command scaffolding (flags, DSN from env/flag, exit-code plumbing).
      No business logic yet
- [x] 3.2 `timeline [--subject] [--since] [--until] [--anchor]`: verify first, print the
      verification header, then rows in sequence order; mark rows from the first break onward and
      still print them
- [x] 3.3 **Test**: seeded incident renders ordered and subject-filtered; a chain tampered at N
      prints an inconsistency header naming N and still prints the tail.
      `TestTimelineRendersOrdered`, `TestTimelineNamesBreakAndPrintsTail`
- [ ] 3.4 `verify [--anchor]`: verification only; exit 0 consistent / 3 inconsistent / 4
      unavailable. **Test**: `TestVerifyExitCodes` drives all three outcomes and asserts the codes
      are distinct — "cannot tell" must not read as "tampered"
- [x] 3.5 `anchor export`: write the current anchor as PEM to stdout with the trust-limit notice.
      **Test**: `TestAnchorExportStatesItsLimit` greps the output for the caveat and asserts it is
      not described as independent proof

## 4. Docs

- [x] 4.1 Record the new decision in `docs/decisions.md`: the public-key chain is part of the
      ledger, not the signer's memory; a forward-secure scheme with unavailable public material
      has no verifiable forward security
- [x] 4.2 Note in `docs/decisions.md` the CLI's trust posture until T-017/T-019: runs for anyone
      with database access, records no accountable viewer (D20 gap), cannot prove completeness
- [x] 4.3 Mark T-010 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| foreign key dropped from migration 002 | `TestEntryCannotReferenceUnstoredEpoch` — an entry referencing an unstored epoch was accepted |
| anchor mismatch check skipped (always self-anchor) | `TestWrongAnchorIsRejected` — a wrong anchor verified as consistent |
| exit codes 3 and 4 collapsed | `TestVerifyExitCodes` assertion, and a duplicate-case compile error — LOUD, not silent |
| verify path depends on a live signer | there is no signer on the verify path; `TestChainSurvivesRestartWithFreshSigner` and `TestVerifyFromStoredChainWithoutSigner` verify through a signer-less process |

**What building the CLI found — the same pattern as the ledger change.** The
public-key chain lived only in the in-process `Signer`. Nothing persisted it, so
a second process could not verify and a restart with a fresh signer orphaned
every prior entry. D30's stated property — "verification takes public material
only" — was true of the algorithm and false of the deployed system, and the old
same-signer restart test hid it (the "convenient subset" the audit-ledger spec
warned about). Fixed by persisting `key_epochs`, verifying from the database, and
pinning to a caller-supplied anchor. Recorded as D32.

End-to-end confirmed against a real Postgres with the built binary: `anchor
export` emits the trust-limit notice and a PEM key; `verify --anchor` exits 0 on
a clean chain; a direct `UPDATE` to one row flips `verify` to exit 3 naming
`first_break`, and `timeline` prints the break in its header, marks the tampered
tail `!!` while leaving the clean prefix unmarked, and still shows every row.
