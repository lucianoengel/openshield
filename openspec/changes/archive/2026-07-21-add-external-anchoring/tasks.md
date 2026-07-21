## 1. Anchor + Witness (core)

- [x] 1.1 `core.Anchor{Sequence, Hash, WitnessSig}`; `core.Witness` (separate keypair);
      `Anchor(seq, hash)` and `VerifyAnchor(a, witnessPub)`; canonical length-prefixed
      `(sequence, hash)` for the witness signature
- [x] 1.2 `VerifyResult` gains `AnchoredThrough uint64`

## 2. Verification integration

- [x] 2.1 `VerifyChain` accepts `[]Anchor` + witness pub; verify each anchor's sig, match its
      (sequence, hash) to the chain; fail naming a violated anchor
- [x] 2.2 Set `AnchoredThrough` = max satisfied sequence; completeness ANCHORED iff the whole
      chain is witnessed, else UNVERIFIED with `AnchoredThrough` reported
- [x] 2.3 No anchors → behaviour byte-for-byte as today

## 3. Storage + head anchoring

- [x] 3.1 Migration `004`: `anchors(sequence, hash, witness_sig)`
- [x] 3.2 postgres `Verify` loads anchors + witness pub; `AnchorHead(ctx, witness)` appends an
      anchor over the current head

## 4. Tests (real Postgres)

- [x] 4.1 **Test**: an anchor verifies with the witness pub; a wrong key fails. `TestAnchorWitnessSig`
- [x] 4.2 **Test**: a partially-anchored chain reports AnchoredThrough=N, completeness UNVERIFIED.
      `TestPartialAnchorBoundary`
- [x] 4.3 **Test**: a fully-anchored chain is ANCHORED. `TestFullyAnchoredComplete`
- [x] 4.4 **Test**: a chain rebuilt shorter than an anchor fails, naming it. `TestTruncationPastAnchorDetected`
- [x] 4.5 **Test**: no anchors → identical to prior behaviour. `TestNoAnchorUnchanged`
- [x] 4.6 **Test**: an anchor whose head-hash mismatches (rewrite) fails. `TestAnchorHashMismatchFails`

## 5. CLI + docs

- [x] 5.1 CLI verification header prints "complete through N, unverified after" when partial
- [x] 5.2 Note in `docs/decisions.md` (new D-number): completeness between anchors; undetectable
      loss window = anchor interval; an anchor is only as good as its witness's independence
- [x] 5.3 Mark T-019 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| anchor hash-match check skipped | `TestTruncationPastAnchorDetected` (pg) + `TestTruncationBeforeAnchorDetected` (core) |
| witness-signature requirement dropped (accept any anchor) | `TestForgedAnchorCannotFailHonestChain` |
| completeness marked ANCHORED on a partial anchor | `TestPartialAnchorReportsBoundary` |

Anchoring is purely additive: with no anchors, `VerifyChain` behaves byte-for-byte
as before (`TestNoWitnessIsUnchanged`), completeness UNVERIFIED. A witness covering
the head flips it to ANCHORED; a partial anchor reports `AnchoredThrough` and keeps
the tail UNVERIFIED; truncating past a witnessed anchor is DETECTED and fails,
naming the anchor — the property the ticket exists to add. A forged anchor (wrong
witness key) is ignored, never able to fail an honest chain. The old
`anchored bool` placeholder (always false in production) is gone; the test that
relied on it was rewritten to use a real witnessed anchor. The CLI header now
prints "complete through seq=N, UNVERIFIED after" for a partial anchor.
