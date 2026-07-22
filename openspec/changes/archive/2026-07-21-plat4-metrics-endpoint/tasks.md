# Tasks — PLAT-4 metrics endpoint (D127)

## 1. Metrics

- [x] 1.1 Server.MetricsHandler (Prometheus text, dependency-free); server binary opt-in /metrics on OPENSHIELD_METRICS_ADDR.

## 2. Proof (guard mutation-tested)

- [x] 2.1 **Test**: the handler emits live counter values in valid Prometheus format (HELP/TYPE/value, text/plain).

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D127.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| hardcode a counter to 0 (not Load()) | the live-value assertion fails |
