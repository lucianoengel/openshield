# Tasks — HON-2 case → legal hold (D122)

## 1. Wire

- [x] 1.1 Migration 012 legal_holds; placeLegalHoldTx + ReleaseLegalHold + IsUnderLegalHold; OpenCase/OpenCaseForIncident place a hold in the case tx.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: opening a case (and from an incident) places an active hold; free subject not held; release ends it; duplicate case idempotent.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D122.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| OpenCase does not place a hold | the subject is not held after opening a case |
| OpenCaseForIncident does not place a hold | the incident subject is not held (needed the test-DROP fix so a leaked hold didn't mask it) |
| IsUnderLegalHold ignores released_at | a released hold still reads as active |
