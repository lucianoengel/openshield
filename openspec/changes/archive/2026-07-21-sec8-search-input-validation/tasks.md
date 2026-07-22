# Tasks — SEC-8 search input validation (D119)

## 1. Fix

- [x] 1.1 parseAlertFilter: 400 on malformed since/until/min_risk/limit; cap limit at maxSearchLimit (also clamped in SearchPeerAlerts).

## 2. Proof (HTTP; guards mutation-tested)

- [x] 2.1 **Test**: malformed params → 400; well-formed → 200; oversized limit accepted+capped; injection test stays green.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D119.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| min_risk malformed silently dropped | a bad min_risk no longer 400s |
| since malformed silently dropped | a bad since no longer 400s |
| limit not validated | a garbage/negative limit no longer 400s |
