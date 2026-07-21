## Why

D89 wired risk-driven continuous verification, but the gateway's RiskStore is empty —
nothing publishes risk, so D89 never fires. This adds the server→gateway risk-publish
channel: the control plane publishes per-subject risk (from peer-UEBA), the gateway
subscribes and populates its RiskStore. The T2 model — server publishes DATA, gateway
decides (D14) — completed end to end.

## What Changes

- `RiskUpdate` proto (subject, risk_score, computed_at) + `natsx.SubjectRisk`.
- `controlplane.Server.PublishRisk(ctx, subject, score)` — publish a RiskUpdate on the
  risk subject; called in `observePeer` after a peer alert is recorded (best-effort).
- `gateway.ApplyRiskUpdate(data, store)` — decode a RiskUpdate and `RiskStore.Set`;
  `gateway.SubscribeRisk(conn, store)` subscribes and applies each update.
- Access-mode binary subscribes to the risk subject (when NATS is configured) and
  populates the live RiskStore, so continuous verification (D89) fires on real risk.

## Capabilities

### Modified Capabilities
- `control-plane`: publishes per-subject risk to the gateways.
- `network-gateway`: subscribes to published risk and populates the RiskStore.

## Impact

- New `RiskUpdate` proto, `natsx.SubjectRisk`, `Server.PublishRisk`,
  `gateway.ApplyRiskUpdate`/`SubscribeRisk`, binary wiring; `docs/decisions.md` D91.
- Proven: ApplyRiskUpdate decodes a RiskUpdate into the RiskStore; PublishRisk marshals
  correctly; the NATS round-trip is integration.
- NOT in scope (stated): per-message signing of risk (transport mTLS D55 authenticates
  the publisher; per-message signing like D50 is a hardening follow-up); subject-space
  unification (endpoint vs gateway subject); the device-posture producer; OIDC.
  Respects D89 (continuous verification), D14/D54 (server informs not commands), D55
  (transport security), D23 (pseudonymous subject).
