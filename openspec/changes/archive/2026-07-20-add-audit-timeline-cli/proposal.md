# Add the audit timeline CLI (T-010)

## Why

T-010 replaces the React investigation UI that was cut from Phase 1: an operator must be
able to reconstruct an incident as an ordered timeline. That is the whole of the ticket as
written, and on its own it is two hours of SQL and formatting.

It is not two hours, because the CLI is the first thing in the system that reads the ledger
**from a different process than the one that wrote it** — and that turns out to be
impossible today.

**The public-key chain is not persisted anywhere.** `postgres.Ledger.Verify` calls
`l.signer.Chain()` and `l.signer.AnchorKey()` on the live in-process `Signer`. Nothing writes
the epoch public keys to the database or to disk. Three consequences, none of them cosmetic:

1. **An independent verifier cannot verify.** D30's stated property — "verification walks the
   public chain from an out-of-band anchor and takes no secret at all" — is true of the
   algorithm and false of the deployed system. There is no way to obtain the chain.
2. **A restart orphans the history.** Construct a fresh `Signer` and every entry written
   before the restart references epoch keys that no longer exist. The chain verifies only for
   the lifetime of one process.
3. **The existing test hid this.** `TestRestartContinuesTheChain` passes the *same* `Signer`
   across the restart. That is the "convenient subset" failure the audit-ledger spec
   explicitly warned about for the attacker test, repeated here in a different test — the
   fixture handed the verifier something the real deployment will not have.

This is the same family of defect as the symmetric-ratchet bug (D30): an implementation that
verified perfectly against tests built from its own assumptions, while the property it claimed
did not hold in the system it will actually run in. It surfaces now because the CLI is the
first honest consumer of that property.

So this change is: persist the key chain, verify from stored public material, and render a
timeline that cannot be mistaken for a verified one when it is not.

## What changes

**Persist the public-key chain** — a `key_epochs` table written as epochs are created, holding
index, public key and the predecessor's signature. Public material only; the private key is
never written. Written in the same transaction that records the first entry of an epoch, so an
entry can never reference an epoch the database does not have.

**Anchor trust becomes explicit.** The anchor public key read from the same database that could
have been rewritten proves nothing on its own. `Verify` gains a caller-supplied *expected*
anchor: given one, it fails if the stored chain does not start there; given none, it verifies
internal consistency and says so. The CLI takes `--anchor` and states plainly which mode it ran
in. Distributing the anchor out-of-band is T-017/T-019 — this change makes the seam real and
the absence visible, and does not pretend to close it.

**`openshieldctl timeline`** — ordered incident reconstruction, filterable by subject, time
range and event, over the persisted ledger.

**Verification is not optional and not a separate subcommand.** The timeline verifies the chain
before it renders and prints the verification state as part of its output. A tool that prints
a plausible-looking incident record without saying whether the record is intact is worse than
no tool: it launders unverified rows into evidence. When the chain is broken the CLI says so
first, names the first broken sequence, and marks the affected rows — it does not refuse to
print, because an operator investigating tampering needs to see the tampered data.

**`openshieldctl verify`** — the chain check alone, exit code non-zero on failure, for cron and
CI use.

## What this does NOT claim or cover

- **It does not make the ledger complete.** Completeness stays UNVERIFIED without an external
  anchor (T-019). The CLI reports that on every invocation rather than in documentation.
- **It does not record who viewed an investigation.** D20 requires that audit trail and T-013
  owns it. This change deliberately does not implement it, because there is no identity to
  record — T-017 has not run, so the honest entry would read "someone with database access".
  Recorded as a known gap in `docs/decisions.md`, not left implicit. **A view-logging seam is
  out of scope on purpose**: a seam that writes an unattributable record would let a future
  reader believe viewer accountability exists.
- **It does not authenticate or authorise the operator.** Anyone who can reach the database can
  run it. That is the deployment posture until T-017 and T-023.
- **It is not an investigation UI.** No saved queries, no correlation, no export formats.
- **It does not touch the core pipeline.** The CLI is a read surface over `internal/store`;
  `internal/core` gains only the anchor parameter on the verification entry point, which is a
  signature change to an existing function rather than a new pipeline concept.

## Decisions

Depends on **D12** (Postgres is the system of record), **D30** (chain plus key evolution;
verification takes public material only) and **D31** (a reachable database is required).

Establishes a new decision: **the public-key chain is part of the ledger, not part of the
signer's memory** — persisted alongside the entries it authenticates, because a forward-secure
scheme whose public material is unavailable to a verifier provides no verifiable forward
security at all.
