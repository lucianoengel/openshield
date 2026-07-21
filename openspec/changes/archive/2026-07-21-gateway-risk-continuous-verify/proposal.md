## Why

Peer-UEBA computes a per-subject risk score (D53/D54) that reaches NO enforcement
point — a dead end. This wires it to the access gateway as continuous verification,
the T2 model the owner confirmed: the server PUBLISHES risk (data), the gateway READS
it as context, and the LOCAL policy decides step-up/deny. The server informs; the
gateway decides; the server never actuates (D14). Scope: the gateway enforcement half;
the server→gateway publish channel is a thin follow-up (A.5b).

## What Changes

- `gateway.RiskStore` — a thread-safe per-subject risk registry: `Set(subject, score)`
  (called by the publish channel later), `Get(subject) (score, has)`. Absent risk has
  `has=false`; the policy treats absent risk per its own rule (absent risk is NOT high
  — analytics-quiet — unlike posture which fails closed, D85).
- `AccessProxy.SetRiskStore(*RiskStore)` — when set, the access handler enriches the
  identity Context with the connecting subject's risk before `Process`, so the policy
  sees `input.context.risk_score` (D85) and can step-up (REDIRECT) or deny (BLOCK) a
  subject whose risk crossed a threshold MID-SESSION — decided LOCALLY (T2).
- High risk reuses existing actions (BLOCK/REDIRECT) — no new action (a dedicated
  STEP_UP is a noted T1 option).

## Capabilities

### Modified Capabilities
- `network-gateway`: the gateway reads published risk and the policy performs
  continuous verification (step-up/deny on rising risk), decided locally.

## Impact

- New `gateway.RiskStore`, `AccessProxy.SetRiskStore` + enrichment; `docs/decisions.md`
  D89. Reuses the D85 context, the D87 access broker, and BLOCK/REDIRECT.
- Proven with real TLS + client certs: the SAME finance identity reaches the service
  with no risk, and is DENIED after risk is published high (access cut mid-session).
- NOT in scope (stated): the server→gateway signed risk-publish channel (A.5b); a
  STEP_UP action (T1); the posture producer; OIDC (A.2b); egress-path risk. Respects
  D54, D14, D53/D28, D85, D87, D69.
