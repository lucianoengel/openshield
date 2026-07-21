# Tasks — fleet alert search (D103)

## 1. Search

- [x] 1.1 AlertFilter + Server.SearchPeerAlerts (parameterized WHERE from set constraints); /search endpoint; mount behind the operator gate.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: filter by subject / min-risk / combined / time window returns the right rows; an injection-shaped subject is data (matches nothing, table intact); /search behind the operator gate (agent → 403).

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D103.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| subject filter dropped | a subject search then returns all subjects |
| min-risk >= flipped to <= | the min-risk search then returns low-risk rows |
| since filter dropped | the time-window search then returns out-of-window rows |
