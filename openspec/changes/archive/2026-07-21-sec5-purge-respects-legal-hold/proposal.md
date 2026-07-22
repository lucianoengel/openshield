## Why

SEC-5 (P1). The retention purge tombstoned any bounded-class entry past its age — including a
subject now under an OPEN INVESTIGATION. Because an entry's `retention_class` is immutable
(migration 010's append-only trigger), a legal hold placed AFTER the entry was written could
not protect it by changing its class, so evidence for an active case could be lawfully erased.
Enterprise legal-hold posture failed here. HON-2 added the hold registry; this makes the purge
respect it.

## What Changes

- `Ledger.Purge` excludes entries whose subject is under an ACTIVE legal hold
  (`legal_holds WHERE released_at IS NULL`), regardless of the entry's routine class and age.

## Capabilities

### Modified Capabilities
- `audit-ledger`: the purge never tombstones a legal-held subject's evidence.

## Impact

- `internal/store/postgres/ledger.go`; `docs/decisions.md` D123.
- Proven (Postgres): two ROUTINE (standard-class) entries past age; a legal hold placed on one
  subject AFTER it was written (the HON-2 registry) — the purge tombstones only the UNHELD
  subject; the held subject's content survives; after RELEASING the hold, a subsequent purge
  tombstones it. Guards mutation-tested (drop the hold exclusion → the held entry is purged;
  ignore released_at → a released hold still protects).
- NOT in scope (stated): appending an attribution audit entry per purge (who/when/policy — the
  SEC-5 (b) "destruction is attributable" half; a follow-up); the non-owner ledger DB role
  (SEC-6, which makes the append-only trigger un-bypassable by a leaked owner credential). The
  age enforcement stays in Purge; the hold is an override on top.
