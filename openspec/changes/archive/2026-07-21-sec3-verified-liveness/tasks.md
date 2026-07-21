# Tasks — SEC-3 verified liveness (+ SEC-11) (D115)

## 1. Fix

- [x] 1.1 Overdue: roster (agent_identities non-revoked) LEFT JOIN verified telemetry. LastSeen: verified filter + error-vs-absence (SEC-11).

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: LastSeen counts verified only (unverified-only agent not seen), unknown = absence; Overdue flags stale + never-seen (roster) + only-unverified (dead-man's-switch holds), not verified-fresh; a closed pool → error not absence (SEC-11).

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D115.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| LastSeen verified filter dropped | an unverified-only agent is then "seen" |
| Overdue verified filter dropped | an only-unverified agent is then not overdue (dead-man's-switch defeated) |
| LastSeen swallows DB error as absence (SEC-11) | a closed pool then returns not-found instead of an error |
