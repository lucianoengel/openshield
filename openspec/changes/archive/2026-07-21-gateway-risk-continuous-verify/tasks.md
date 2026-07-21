# Tasks — risk-driven continuous verification (D89)

## 1. Risk store

- [x] 1.1 `gateway.RiskStore` — thread-safe per-subject risk: `NewRiskStore()`, `Set(subject string, score float64)`, `Get(subject string) (float64, bool)`. Absent subject → `has=false`.

## 2. Access enrichment

- [x] 2.1 `AccessProxy.SetRiskStore(*RiskStore)` (optional setter). When set, `ServeHTTP` enriches the identity Context before Process: `idCtx := id.Context(); if s, ok := risk.Get(id.Subject); ok { idCtx.RiskScore = s; idCtx.HasRiskScore = true }`.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test** (real TLS + client certs): a policy authorizing role finance but BLOCK on risk >= 0.8; resolve the finance cert's subject; NO risk published → the finance client REACHES the service; after `RiskStore.Set(subject, 0.95)` → the SAME client is DENIED 403, service NEVER reached (continuous verification, local decision).
- [x] 3.2 **Test**: `RiskStore` unit — Set/Get; an absent subject returns `has=false`.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D89: risk-driven continuous verification closes the D54 dead-end — RiskStore holds published per-subject risk, the access proxy enriches the identity Context, the LOCAL policy step-ups/denies on high risk (T2: server publishes data, gateway decides, server never actuates, D14); absent risk is not high (unlike posture, D85); reuses BLOCK/REDIRECT; the publish channel is A.5b.
- [x] 4.2 `openspec validate gateway-risk-continuous-verify --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| access does not enrich the identity context with risk | `TestRiskContinuousVerification` |
| RiskStore.Get always reports absent | `TestRiskStoreSetGet`, `TestRiskContinuousVerification` |

THE VERDICT (D89): the gateway reads published per-subject risk (RiskStore) and the LOCAL policy
step-ups/denies on it — continuous verification, closing the D54 dead-end. The server publishes DATA,
the gateway decides (T2/D14), the server never actuates. Absent risk is not high (opposite fail-direction
from posture, D85). Reuses BLOCK/REDIRECT. Proven with real TLS + client certs (access cut mid-session).
NOT in scope: the publish channel (A.5b), STEP_UP action (T1), posture producer, OIDC (A.2b), egress
risk.
