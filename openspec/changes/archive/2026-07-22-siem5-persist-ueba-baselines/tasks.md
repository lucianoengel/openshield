## 1. Analyzer snapshot/restore

- [x] 1.1 Add `SubjectState{Subject string; Count float64; Last time.Time}`, `Analyzer.Snapshot() []SubjectState` (under lock, verbatim count+last), and `WithSnapshot([]SubjectState) Option` seeding `New`.
- [x] 1.2 Test the exact round-trip: observe subjects, `Snapshot`, build a new analyzer `WithSnapshot`, `ContextFor` yields the same risk; empty snapshot = cold analyzer.
- [x] 1.3 Mutation-test restore fidelity: flatten every restored subject to the SAME count → the round-trip risk differs (test fails), proving per-subject Count is load-bearing. (Note: halving ALL counts is scale-invariant for a z-score, so the shape-breaking mutation is the correct one.)

## 2. Migration

- [x] 2.1 Add `019_ueba_baselines.sql` (subject PK, count, last_seen, updated_at); rely on the 017 default-privilege grant for the writer role.
- [x] 2.2 Bump the migration-count test 18 → 19.

## 3. Control-plane persistence

- [x] 3.1 `PersistBaselines(ctx)` UPSERTs the analyzer snapshot into `ueba_baselines` (`ON CONFLICT (subject) DO UPDATE`); no-op when peer-UEBA disabled.
- [x] 3.2 `loadBaselines(ctx)` SELECTs into `[]SubjectState`.
- [x] 3.3 `EnablePeerUEBA` loads persisted baselines and seeds the analyzer via `WithSnapshot`, best-effort (load failure logs, cold-starts, never blocks enable).
- [x] 3.4 Real-Postgres test: observe on instance A, persist, fresh instance B `EnablePeerUEBA` → the baseline/risk survives; a cold B has none.

## 4. Binary wiring

- [x] 4.1 `cmd/openshield-server`: schedule periodic `PersistBaselines` via `retain.Loop` (interval `OPENSHIELD_UEBA_PERSIST_INTERVAL`, default 5m) and persist once on graceful shutdown, only when peer-UEBA is enabled.

## 5. Gate

- [x] 5.1 `openspec validate siem5-persist-ueba-baselines --strict` passes.
- [x] 5.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; archive + sync specs + commit/push.
