## Context

The ledger's forward-security proof (D30) rests on a public-key chain that verification walks
from an out-of-band anchor. That chain currently lives only in `core.Signer`, an in-memory
object. Nothing persists it. `postgres.Ledger.Verify` reaches into the live signer for it,
which works exactly as long as the process that wrote the entries is the process reading them.

The CLI (T-010) is the first consumer that is a different process. It cannot verify, because it
has no signer and there is nowhere to load the chain from. Building the CLI therefore forces
the persistence that D30 already assumed existed.

Current state worth stating precisely:
- `audit_entries.key_epoch` records *which* epoch signed each row, but the epoch public keys
  themselves are unstored.
- `Verify` takes no expected anchor. It trusts `signer.AnchorKey()`, i.e. it trusts the same
  process to tell it what the anchor is — no external check is possible.
- `TestRestartContinuesTheChain` reuses one `Signer` across the "restart", so the orphaning
  that a real restart causes is invisible to the suite.

## Goals / Non-Goals

**Goals:**
- Persist the public-key chain so any process with database access can verify using public
  material only, satisfying D30 in the system and not merely in the algorithm.
- Let a caller supply the anchor they trust, so verification against an untrusted database is
  distinguishable from verification that trusts the database to describe itself.
- Render an ordered incident timeline whose output can never be mistaken for verified when it
  is not.

**Non-Goals:**
- External anchoring / witnessing (T-019). The seam is made explicit; the guarantee is not
  provided.
- Operator identity, authn/authz, and who-viewed-an-investigation logging (T-013, T-017). No
  identity exists to record yet, and a seam that records an unattributable view would be worse
  than its absence.
- Any change to the pipeline stage model. `internal/core` gains one parameter on one function.

## Decisions

### Persist the chain in a `key_epochs` table
Columns: `index BIGINT PRIMARY KEY`, `public_key BYTEA NOT NULL`, `sig_by_prev BYTEA` (null for
the anchor). Public material only — asserted by a test that inspects the table's columns and
fails if any name suggests private key bytes, and by the fact that `core.KeyEpoch` carries no
private field to write.

Epoch 0 is inserted when the ledger is first opened on an empty database. Each subsequent epoch
is inserted **in the same transaction** as the first entry that uses it. An entry referencing an
epoch the `key_epochs` table lacks must be impossible by construction, not merely unlikely —
that is the invariant a foreign key from `audit_entries.key_epoch` to `key_epochs.index`
enforces, and the migration declares it.

This means `Append` becomes transactional: begin, insert the epoch row if this append triggered
an evolution, insert the entry, commit. The evolution-after-store ordering from the current code
is preserved — the key evolves only once the transaction that will use it has the row.

### Load the chain on `Open`, do not depend on a live signer for verification
`Verify` reads `key_epochs` and reconstructs `[]core.KeyEpoch`, then calls `core.VerifyChain`
with it. A verifier constructed with no signer at all (the CLI's case) can still verify. The
signer remains required for `Append` — writing needs a private key — but reading does not.

### `Verify` takes an expected anchor
`core.VerifyChain` already takes `anchor` and `anchored`. The gap is at the `Ledger.Verify`
boundary, which fabricates the anchor from the signer. Change the interface:

    Verify(ctx context.Context, expectedAnchor ed25519.PublicKey) (VerifyResult, error)

- Non-nil `expectedAnchor`: the stored chain must start with it, or verification fails with a
  distinct reason. This is verification that does not trust the database.
- Nil `expectedAnchor`: verify internal consistency against whatever anchor the chain declares,
  and force `Completeness = Unverified` with a reason naming the missing anchor. This is the
  honest degraded mode, not a silent one.

The existing single-caller (`Dispatcher` path via tests) passes nil and its behaviour is
unchanged. Anchored-mode completeness still requires T-019 and stays out of reach.

### The timeline verifies first and reports state inline
`openshieldctl timeline [--subject S] [--since T] [--until T] [--anchor FILE]`:
1. Load and verify. Print a header line stating consistency, the validated range, completeness,
   and which anchor mode ran.
2. Render rows in `sequence` order. If the chain broke at sequence N, rows from N onward are
   marked, and the header names N first.
3. Never silently drop the broken tail — an operator investigating tampering must see it.

`openshieldctl verify [--anchor FILE]`: verification only, non-zero exit on inconsistency, for
cron/CI. Exit codes are part of the contract (0 consistent, 3 inconsistent, 4 unavailable) so a
scheduled check can act on them.

### Anchor file format
The anchor is a PEM-wrapped Ed25519 public key, read from `--anchor`. `openshieldctl anchor
export` writes the current anchor to stdout so an operator can capture it out-of-band on day
one. Capturing it *from the same host* gains little (design.md open question from the ledger
change); the CLI documents that in the export output rather than implying the captured file is
independently trustworthy.

## Risks / Trade-offs

- **The foreign key couples entry insertion to epoch insertion.** A bug that evolves the signer
  without writing the epoch row now fails the append loudly (FK violation) instead of silently
  producing an unverifiable entry. That is the intended direction: fail at write, not at audit.
- **Transactional append is slower.** Irrelevant here — append is off the permission-window hot
  path by construction (D24); the ledger write already happens after the pipeline returns.
- **`Verify` signature change ripples to every caller.** There is essentially one, and the
  change is additive (a new parameter). Chosen over a second method because two verify methods
  invite a caller to pick the one that trusts the database without meaning to.
- **The anchor story is still incomplete.** Exporting the anchor from the host that could have
  rewritten the log is theatre if that host is the adversary. The CLI states this rather than
  hiding it; the real fix is T-019 and is not in scope. The value delivered now is that an
  anchor captured while the host is *honest* becomes checkable later — which is exactly the
  forward-security bet the ledger already makes.
