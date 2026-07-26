## 1. Lifecycle

- [x] 1.1 Migration: `incidents` gains `transitioned_by TEXT`, `transitioned_at TIMESTAMPTZ`; bump the
  migration count in `postgres_test.go`.
- [x] 1.2 A state rank table (`open < acknowledged < triaged < contained < closed`) and
  `TransitionIncident(ctx, id, to, operator)` that refuses a backward or unknown target atomically, records
  who/when, and returns a typed error for each refusal.
- [x] 1.3 Tests: forward transition applies and is attributed; backward is refused and the state is
  unchanged (**mutation:** drop the rank check → FAILS); unknown state refused; unknown incident is
  not-found.

## 2. Scheduled correlation

- [x] 2.1 `RunCorrelationLoop(ctx, interval, burstRule, xdrRule)` materializing BOTH rules per tick via
  `retain.Loop`, with failures counted and logged rather than stopping the loop.
- [x] 2.2 Wire it inside `Leader.Run`'s elected context in `cmd/openshield-server`, env-gated by interval.
- [x] 2.3 Test: with alerts seeded and NO request to the incidents endpoint, an incident exists and a
  notification was delivered within an interval. **Mutation:** remove the loop's materialize call → FAILS.

## 3. Operator surface

- [x] 3.1 `POST /incidents/transition?id=N&to=<state>`, responder tier, operator from the verified cert;
  400 on an unknown state, 409 on a backward transition, 404 on an unknown incident.
- [x] 3.2 Endpoint test for each outcome.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Roadmap + decision register (name the "correlation only ran on a GET" gap this closes).
- [x] 4.3 Commit `SOAR-2`, sync spec, archive.
