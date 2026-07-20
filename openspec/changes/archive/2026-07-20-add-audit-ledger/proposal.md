## Why

A Decision that is not durably recorded did not happen. Phase 1 is observe-and-audit only (D1),
so the audit ledger is not a supporting feature — it is the entire deliverable. Everything built
so far produces Decisions that currently go nowhere.

The ledger must also be **tamper-evident**, and that word is doing precise work. Round-1 review
established that "tamper-proof" is unachievable in a single self-hosted trust domain: a log
signed by the same root process that writes it proves nothing about tampering by that process.
What is achievable offline is *forward integrity* — an attacker who compromises the agent now
cannot alter entries from before the compromise (D12).

This change covers T-026 (schema and migrations) and T-009 (the ledger). They are one thing:
the schema exists to serve the ledger, and the ledger is hash-chained, so **adding a column
later is not an ordinary migration — it breaks chain continuity**. Every column D12, D20 and D27
require has to be right at the first migration, for the same reason `context_version` was added
to `Decision` before any consumer existed.

## What Changes

- PostgreSQL schema for the audit ledger, with forward-only versioned migrations.
- A hash chain over entries: each entry commits to its predecessor.
- **Key-evolving forward integrity**: the signing key is ratcheted and the prior key destroyed,
  so a post-compromise attacker cannot forge or alter pre-compromise entries.
- An `Append`/`Verify` interface in core; the Postgres implementation lives outside it, matching
  the transport pattern (core must not import a database driver).
- Columns for D20 (retention class, purpose, pseudonymous subject) and D27 (`context_version`)
  present from the first migration, whether or not anything writes them yet.
- Verification that detects tampering, and reports **which** entry broke the chain.

## Capabilities

### New Capabilities
- `audit-ledger`: append semantics, the hash chain, forward integrity, verification, and the
  precise boundaries of what the tamper-evidence claim covers.

### Modified Capabilities
None.

## Impact

- **Code:** `internal/core` gains the ledger interface. `internal/store/postgres` implements it.
  The dispatcher's `OnOutcome` becomes the ledger's caller.
- **Dependencies:** a Postgres driver, confined to `internal/store`. The existing
  `check-core-deps.sh` must be extended so core cannot import it.
- **Ops:** a database becomes required for the agent to record anything, which is a real
  deployment constraint worth stating plainly rather than discovering.

## What this change does NOT do

- **Does not make the log tamper-proof, and must never claim to.** An attacker holding root can
  still suppress future entries, fabricate forward from the moment of compromise, or delete the
  log outright. Forward integrity protects the *past*, not the present or future.
- **Does not implement external anchoring (T-019).** Anchoring needs a second trust domain that
  does not exist yet. But the entry format and verification interface must accommodate it now,
  or T-019 becomes another chain-breaking migration. The gap is explicit: between anchors, a
  root attacker can destroy the whole chain and verification will report only that it is gone.
- **Does not enforce retention (T-013).** The columns exist; the purge job does not.
- **Does not store evidence or file content.** The ledger records Decisions and outcomes.
- **Does not provide investigation queries (T-010).**
