## 1. The e2e test

- [x] 1.1 `e2e/e2e_test.go` (`//go:build e2e`): read OPENSHIELD_E2E_NATS / OPENSHIELD_E2E_DSN /
      OPENSHIELD_E2E_EVENT; publish Event + ClassificationSummary + Decision via nats.Transport
- [x] 1.2 Poll `fleet_telemetry` for the event id until 3 rows (event/classification/decision) or a
      deadline; fail loudly on timeout

## 2. Orchestration

- [x] 2.1 `deploy/e2e.sh`: stop openshield-pg; podman-compose up -d --build; wait for "subscribing
      to telemetry"; run the tagged test with a unique event id; teardown + restore openshield-pg
      via a trap regardless of result

## 3. Run it + docs

- [x] 3.1 Actually run `deploy/e2e.sh` against real containers; record the result
- [x] 3.2 Note the e2e in deploy/README.md
- [x] 3.3 Validate; archive

## Verification performed

**Ran `deploy/e2e.sh` for real, and it passed live:**

```
==> freeing port 55432 (stopping dev openshield-pg)
==> bringing up the stack (building the server image)
==> waiting for the server to subscribe
==> server ready; running the e2e test (event id e2e-1417960-1784634004)
--- PASS: TestContainerRoundTrip (0.21s)
    e2e OK: 3 telemetry rows for "e2e-..." persisted by the containerised server
==> tearing down
```

An Event + ClassificationSummary + Decision published over the REAL NATS container
were persisted by the actual `openshield-server` BINARY (in its container) to the
REAL Postgres container, and read back — all three kinds. Teardown ran on exit and
restored the dev `openshield-pg`; a follow-up unit-test run against the restored DB
passed, confirming the e2e leaves the machine as it found it. The test is
build-tagged `e2e` so it stays out of the normal suite.
