## Context

The ledger is hash-chained and forward-secure (D12/D30). `VerifyChain` walks entries checking:
(1) `prev_hash` links to the previous entry's hash; (2) the stored hash equals
`sha256(canonicalBytes(entry))`; (3) the signature is valid for the epoch key over the hash. Check
(2) is the obstacle to retention: erasing an entry's content changes `canonicalBytes`, so the
recompute no longer matches the stored hash.

The schema already has `retention_class`, `purpose`, `subject_id`. No purge job, no exclusion, no
view-audit exists.

## Goals / Non-Goals

**Goals:**
- Erase expired personal data without breaking chain verification.
- Retention classes → durations, with investigation holds.
- Exclusion at the source: an excluded path produces no event.
- View accountability: reading an investigation writes an audit entry (OS user, labelled).
- Pin pseudonymisation and purpose with tests.

**Non-Goals:**
- Four-eyes / employee-notice (enforcement-phase, no control plane yet).
- Authenticated identity (T-017).
- Making erasure defeat a root attacker (impossible without T-019; stated).

## Decisions

### Tombstone: erase content, keep the skeleton, verify differently
Migration adds `tombstoned_at TIMESTAMPTZ` (null = live). Purge, for each expired entry, sets
`tombstoned_at = now()` and NULLs the personal-data columns (subject_id, decision_id, event_id,
reason, policy fields, purpose) — keeping `sequence, prev_hash, hash, sig, key_epoch`.

`core.Entry` gains `Tombstoned bool`. `VerifyChain`, for a tombstoned entry:
- still checks `prev_hash` links to the previous hash (chain continuity intact);
- still checks the signature over the STORED hash (authenticity of the original intact);
- SKIPS the content recompute (2), because the content is intentionally absent.

So a tombstoned entry contributes its original hash to the chain and remains an authenticated
link; only the "hash matches current content" check is waived, and only for it. `VerifyResult`
gains a `Tombstoned int` count so verification reports erasure openly — an auditor sees N entries
were purged, distinguishing "erased under retention" from "silently missing".

Why not delete: deleting shifts sequence numbers and removes hashes later entries link to,
breaking the chain irreparably. Tombstoning keeps every link.

The residual, stated: a root attacker can tombstone+erase a LIVE entry to hide it, and
verification would accept it (it only knows the row is tombstoned, not whether the purge was
lawful). This is no worse than the existing truncation limit — both need T-019's external anchor
to distinguish lawful from malicious loss — and the same completeness caveat covers it.

### Retention durations, with a hold
`RetentionShort=30d, Standard=365d, Investigation=held` (a sentinel meaning "never by routine
purge"). `Purge(ctx, now)` tombstones entries whose `appended_at` is older than their class's
max age; Investigation entries are skipped. Durations are constants now, config later.

### Exclusion at the source
`core.ExclusionSet`: a set of path prefixes and time windows. A connector consults it and does
NOT emit an event for an excluded subject. Exclusion is a pure, testable predicate
(`Excluded(path, at) bool`); wiring it into the (future real) fanotify connector is a one-line
guard at event production. Testing here is the predicate + a demonstration that a stage pipeline
fed an excluded event never produces a Decision — but the stronger, honest form is that the event
is never produced, so the test asserts the connector-level skip.

### View accountability
`Ledger.RecordView(ctx, viewer, subjectFilter)` appends a view entry — an ordinary ledger entry
with an outcome_kind of "investigation-viewed" and the viewer string. The CLI's `timeline`/`verify`
call it, passing the OS user (`os.Getenv("USER")` / uid) labelled `unauthenticated:`. It is a
normal chained entry, so viewing is itself tamper-evident.

## Risks / Trade-offs

- **Touching VerifyChain again.** It has bitten us repeatedly. Mitigation: the tombstone branch is
  small and explicit, and tested hard — a live entry that is edited still fails; a tombstoned
  entry with a broken link still fails; a tombstoned entry with a forged signature still fails;
  only the content-recompute is waived, and a test proves the OTHER checks still run on tombstoned
  rows (the exact gap that hid the original signature bug).
- **Tombstone-to-hide.** Stated above; bounded by the existing completeness caveat and T-019.
- **View-audit inflates the ledger.** Every read writes an entry. Acceptable and intended — who
  looked is itself audit-worthy (D20) — and retention purges view entries like any other.
- **OS-user viewer is weak.** Labelled unauthenticated; real identity is T-017. Weak-but-labelled
  beats absent-and-silent.
