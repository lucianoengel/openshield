# Tasks — fleet correlation engine (D104)

## 1. Correlation

- [x] 1.1 CorrelationRule + Server.Correlate (GROUP BY/HAVING over peer_alerts, parameterized) + Incident; /incidents endpoint behind the operator gate.

## 2. Proof (Postgres; guards mutation-tested)

- [x] 2.1 **Test**: a 4-alert burst correlates into one incident (count, peak risk, first<last); single-alert and out-of-window subjects do not; a raised risk floor drops it below threshold; /incidents agent→403.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D104.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| HAVING count threshold weakened to 1 | a single-alert subject then becomes an incident |
| window cutoff neutralized | out-of-window alerts then count toward an incident |
| risk floor >= flipped to <= | the risk filter then selects the wrong alerts |
