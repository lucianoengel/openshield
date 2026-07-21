## 1. Tombstone: erase without breaking the chain

- [x] 1.1 Migration `003`: add `tombstoned_at TIMESTAMPTZ` (null = live) to `audit_entries`
- [x] 1.2 `core.Entry` gains `Tombstoned bool`; `VerifyChain` for a tombstoned entry checks the
      prev-hash link and the signature over the stored hash, and SKIPS the content recompute
- [x] 1.3 `core.VerifyResult` gains `Tombstoned int`; verification counts tombstoned entries
- [x] 1.4 postgres `Verify` loads `tombstoned_at` → `Entry.Tombstoned`; a tombstoned row's null
      content columns read back as empty without breaking the scan

## 2. Purge job

- [x] 2.1 `RetentionClass` → max age (`Short=30d`, `Standard=365d`, `Investigation=held` sentinel)
- [x] 2.2 postgres `Purge(ctx, now)`: for entries past their class age (Investigation exempt), set
      `tombstoned_at` and NULL subject_id, decision_id, event_id, reason, policy_id, policy_version,
      purpose — keeping sequence, prev_hash, hash, sig, key_epoch
- [x] 2.3 Purge is idempotent and returns the count tombstoned

## 3. Tests — retention (against real Postgres)

- [x] 3.1 **Test**: tombstone a middle entry → whole chain still verifies. `TestTombstonedChainVerifies`
- [x] 3.2 **Test**: a tombstoned entry with a corrupted prev-hash link fails.
      `TestTombstonedLinkStillChecked`
- [x] 3.3 **Test**: a tombstoned entry with a corrupted signature fails.
      `TestTombstonedSignatureStillChecked` — the exact gap that hid the original sig bug
- [x] 3.4 **Test**: purge tombstones expired routine entries and skips investigation-class.
      `TestPurgeRespectsHold`
- [x] 3.5 **Test**: after purge, the personal-data columns of a tombstoned row are empty.
      `TestPurgeErasesContent`
- [x] 3.6 **Test**: verify reports the tombstoned count. `TestVerifyReportsTombstoneCount`

## 4. Exclusion lists

- [x] 4.1 `core.ExclusionSet`: path-prefix and time-window rules; `Excluded(path, at) bool`
- [x] 4.2 **Test**: excluded path/time predicate; an excluded subject yields no event through the
      producing path. `TestExcludedSubjectProducesNoEvent`

## 5. View accountability

- [x] 5.1 `Ledger.RecordView(ctx, viewer)` appends an entry with outcome_kind
      "investigation-viewed" and the viewer string
- [~] 5.2 CLI wiring DEFERRED to T-023: recording a view is an Append (needs the signer), and the CLI is a pure verifier that must hold no signer (D30). `TestVerifierCannotRecordView` pins this boundary. The mechanism (5.1) is built and tested; the read-surface wiring belongs to the write-capable query service
- [x] 5.3 **Test**: a view writes a chained entry carrying the unauthenticated label.
      `TestViewIsRecorded`

## 6. Pin existing invariants + DPIA

- [x] 6.1 **Test**: the boundary summary's subject is pseudonymous; an event carries a purpose.
      `TestPseudonymousAndPurposePinned`
- [x] 6.2 Ship a DPIA template in `docs/dpia-template.md` (the one purely-documentary L1 item)
- [x] 6.3 Note in `docs/decisions.md` (new D-number) the tombstone decision and the four-eyes /
      notice deferral to the enforcement phase

## 7. Docs

- [x] 7.1 Mark T-013 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| signature check waived for tombstoned rows too | `TestTombstonedSignatureStillChecked` (real Postgres) |
| prev-hash link check waived for tombstoned rows | `TestTombstonedLinkStillChecked` |
| investigation hold removed (MaxAge bounded) | `TestRetentionExpiryAndHold` (the real single-point guard) |
| exclusion predicate always false | `TestExclusion*`, `TestExcludedSubjectProducesNoEvent` |

**The central tension, resolved (D36).** Retention purge must erase expired personal
data; the ledger is hash-chained, so deleting a row breaks the chain. Tombstoning
keeps the skeleton (sequence/link/hash/sig) and waives ONLY the content recompute
for erased rows — the link and signature are still checked, proven by the two
tombstone-attack tests above. The signature-still-checked test guards the exact
gap that once let a valid hash hide an invalid signature; it was written to fail
if that waiver were widened.

**A boundary implementation surfaced.** View accountability needs an Append,
which needs the signer; the CLI is a signer-less verifier by design (D30). So
`RecordView` is built and tested on the write-capable ledger, `TestVerifierCannotRecordView`
pins that a verifier cannot append, and wiring the view behind the read CLI is
deferred to the write-capable query service (T-023) — recorded, not dropped.

The investigation hold is defense-in-depth (MaxAge returns held AND Purge's loop
excludes Investigation); neither single mutation breaks it, and the MaxAge guard
is caught by `TestRetentionExpiryAndHold`.
