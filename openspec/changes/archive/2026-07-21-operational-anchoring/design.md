## Context

`Ledger.AnchorHead(ctx, *core.Witness)` reads the head `(sequence, hash)`, signs
it with the witness, and inserts into `anchors`. `Verify` uses `l.WitnessPub`
(a field, empty by default) to check stored anchors → `CompletenessAnchored`.
`OpenForVerify(dsn)` returns a signer-less `*Ledger` whose pool `AnchorHead` uses
— so a witness process needs only the witness key and the DSN, never the ledger
signer. `core.NewWitness` generates a keypair but there is no way to persist and
reload one.

## Goals / Non-Goals

**Goals:**
- Anchoring is RUNNABLE (a binary) and SCHEDULABLE (a timer), under a persistent,
  externally-held witness key.
- An auditor can verify completeness against the witness public key and see the
  range move off `UNVERIFIED`.
- The witness process holds only the witness key, never the ledger signer.

**Non-Goals:**
- A hosted transparency service or WORM integration — the tool is designed to RUN
  in an external trust domain; providing that domain is the operator's job.
- Automatic witness-key rotation / multi-witness quorum — a single witness key,
  documented; rotation is a later concern.
- Changing `AnchorHead`, `Verify`, or the anchor wire format.

## Decisions

**Witness persistence via the raw Ed25519 private key.** `WitnessFromKey(priv
ed25519.PrivateKey) *Witness` reconstructs a witness; `(w *Witness) PrivateKey()`
exposes the bytes to save. The tool reads/writes the raw 64-byte private key and
32-byte public key (matching `escrow-keygen`'s raw-bytes convention), not PEM —
these are keys, not certificates.

**A separate authority binary, not openshieldctl.** Witnessing SIGNS (with the
witness key) and WRITES an anchor row. openshieldctl "holds no signer and can
produce no entry"; putting witnessing there breaks that. `cmd/openshield-anchor`
is the witness authority, mirroring how `openshield-provision` is the credential
authority. It uses `OpenForVerify` so it cannot hold or use the ledger signer.

**openshieldctl gains read-only witness verification.** `verify --witness <pub>`
loads the witness PUBLIC key and sets `Ledger.WitnessPub` before `Verify`, so an
auditor can confirm `CompletenessAnchored`. This is pure verification with public
material — openshieldctl stays signer-less. Without `--witness`, behaviour is the
honest `UNVERIFIED` degraded mode, unchanged.

**One-shot by default; the timer owns the cadence.** `openshield-anchor` anchors
once and exits — the natural shape for a `systemd .timer` or cron, which owns the
schedule (and therefore the undetectable-loss window). `--interval D` runs a loop
for hosts without a scheduler. Either way the tool logs the anchored sequence.

**Proof that it MOVES completeness.** A test reconstructs a witness from a SAVED
key, anchors the head, sets `WitnessPub`, and asserts `Verify` returns
`CompletenessAnchored` (not `UNVERIFIED`) — the operational property, not just
that `AnchorHead` inserts a row. `deploy/observe-e2e.sh` is extended: after the
ALERT lands, the `openshield-anchor` BINARY witnesses the head and
`openshieldctl verify --witness` shows the range anchored.

## Risks / Trade-offs

- **Witness custody is the whole guarantee (T-019).** A witness key on the same
  host as the ledger attests to little — an attacker with the host holds both and
  re-anchors a rewritten chain. The tool makes anchoring runnable; it cannot make
  the operator hold the key elsewhere. Stated plainly in the tool's output and
  docs: run it from a trust domain you do not control.
- **The loss window is the schedule.** Everything appended since the last anchor
  can still be truncated undetected. Documented on the timer: a shorter interval
  is a smaller window at more anchor rows.
- **A signer-less ledger that writes anchors.** `AnchorHead` inserts into
  `anchors` (not `audit_entries`, so the D63 append-only trigger does not apply);
  the witness process has DB write access to the anchors table only in practice —
  least-privilege for the anchor role is the same follow-up as the ledger role
  (D63), noted, not solved here.
