## Why

The roadmap states PLAT-9's requirement precisely: *"restore must re-verify the hash chain + anchors, not
just the bytes"*. Today there is no restore path at all, and `openshieldctl verify` — which does verify —
is not it, because it is allowed to degrade honestly to `UNVERIFIED` when no witness key is supplied.

That degradation is right for a routine check and **wrong for a restore**. The question being asked after
a restore is "did my evidence survive?", and the most likely way it did not is **truncation**: a backup
taken mid-write, a partial restore, a table restored without its tail. A truncated ledger is *internally
consistent* — it hashes perfectly, it just stops early — so chain verification alone reports OK. Only an
external anchor detects it, and only up to `AnchoredThrough`.

A restore report that prints OK while unable to detect the most likely restore failure is worse than no
report.

## What Changes

- **`openshieldctl restore-verify`**: a post-restore gate that verifies the chain **and requires anchor
  completeness**. A witness key is **mandatory** — without one the command fails rather than degrading,
  because "I cannot tell" must not render as success.
- **The unproven tail is reported explicitly.** Completeness is proven only to `AnchoredThrough`; entries
  after it can still be truncated undetectably. The command states how many entries sit beyond the anchor
  rather than letting `consistent=true` imply the whole ledger survived.
- **Distinct exit codes** for the three answers an operator needs to tell apart: verified, tampered/
  truncated, and cannot-determine.

## Capabilities

### Modified Capabilities
- `audit-ledger`: adds a restore-verification mode that refuses to report success without anchor-proven
  completeness, and reports the tail an anchor does not cover.

## Impact

- **New code**: `cmd/openshieldctl` gains `restore-verify`; the verification itself is the existing
  `VerifyChain`/anchor path, reused rather than reimplemented.
- **No migration, no proto change, no new dependency.**
- **Honest scope**: this is the *verification* half. It does **not** take backups — `pg_dump` and the
  agent ledger files are the operator's, and wrapping them would imply a backup product this is not. It
  does not restore anything. The remaining PLAT-9 items — rolling upgrade with version-skew tolerance and
  rollback, node/DB recovery, the DR runbook, and the documented deployment footprint — are separate.
  Anchor coverage is only as good as the witness's cadence: a ledger anchored hourly cannot prove the last
  hour, and the command says so rather than implying otherwise.
