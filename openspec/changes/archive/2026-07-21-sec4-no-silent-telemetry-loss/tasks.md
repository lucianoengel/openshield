# Tasks — SEC-4 no silent telemetry loss (D116)

## 1. Fix

- [x] 1.1 natsErrorHandler (count DroppedMessages + log) via nats.ErrorHandler; subscribeCounted sets explicit SetPendingLimits on every subscription.

## 2. Proof (embedded NATS; guard mutation-tested)

- [x] 2.1 **Test**: a flooded blocking subscriber with a tiny pending limit fires the ErrorHandler (drops observed, not silent zero); the server handler increments DroppedMessages per error.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D116.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| swallow the error handler (don't count) | DroppedMessages stays 0, the in-package test fails |
