## Context

`core.VerifyChain` already returns `Consistent`, `Completeness` and `AnchoredThrough`, and `openshieldctl
verify` already exposes it. What does not exist is a *restore gate* — and the difference is not cosmetic.

## Goals / Non-Goals

**Goals:** a post-restore verification that cannot report success without anchor-proven completeness, that
states the unproven tail, and whose exit codes separate the three outcomes.

**Non-Goals:** taking backups, performing restores, rolling upgrade/skew/rollback, the DR runbook, the
deployment footprint.

## Decisions

### Restore verification refuses to degrade, where routine verification is right to

`verify` degrades to `UNVERIFIED` without a witness key, and that is honest for a routine check: it says
what it could and could not establish. A restore is a different question. The operator is asking "did my
evidence survive?", and the answer "the chain hashes correctly" is one a **truncated** ledger also gives —
it is internally consistent, it simply stops early.

Truncation is also the most likely restore failure: a dump taken mid-write, a partial restore, a table
restored without its tail. Only an external anchor catches it. So the witness key is mandatory here, and
"I cannot tell" is a failure rather than a success with a caveat, because a caveat in a restore report is
read as OK.

### The unproven tail is stated, not implied away

`AnchoredThrough` bounds what completeness proves. Reporting `consistent=true` without also reporting how
many entries lie beyond the anchor would let an operator conclude the whole ledger survived, when what was
established is "everything up to sequence N did".

This is the same discipline as SOAR-6 reporting the excluded population beside every average: a measure
without its denominator reads as more than it is.

### Three exit codes, because there are three different answers

Verified, tampered-or-truncated, and cannot-determine are three distinct operational situations —
"proceed", "your evidence is damaged, do not proceed", and "your monitoring is broken, fix that first".
Collapsing the last two into "not OK" would send an operator hunting for tampering when the real problem
is a missing witness key.

## Risks / Trade-offs

- **A ledger anchored hourly cannot prove the last hour** → stated by the command; anchor coverage is a
  cadence decision, not something verification can improve.
- **Mandatory witness key makes this unusable where anchoring was never configured** → deliberate: a
  deployment with no anchors cannot demonstrate a restore preserved its evidence, and pretending otherwise
  is the failure this exists to prevent.

## Migration Plan

Additive: a new subcommand. `verify` is unchanged, including its honest degraded mode.

## Open Questions

- Whether a deployment should be able to *require* anchoring at ingest time, so the "no anchors" case
  cannot arise — a policy question rather than a verification one.
