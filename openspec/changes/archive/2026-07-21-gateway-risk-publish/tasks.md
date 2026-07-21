# Tasks — risk-publish channel (D91)

## 1. Proto + subject

- [x] 1.1 `RiskUpdate` proto (subject, risk_score, computed_at); `natsx.SubjectRisk`. Regenerated.

## 2. Server publish

- [x] 2.1 `controlplane.Server.PublishRisk(ctx, subject, score)` — marshal a RiskUpdate, publish on SubjectRisk via s.conn (best-effort). Call it in `observePeer` after `recordPeerAlert`.

## 3. Gateway subscribe

- [x] 3.1 `gateway.ApplyRiskUpdate(data []byte, store *RiskStore) error` — unmarshal RiskUpdate, `store.Set(subject, risk_score)`.
- [x] 3.2 `gateway.SubscribeRisk(conn *nats.Conn, store *RiskStore) error` — subscribe SubjectRisk, ApplyRiskUpdate each message.
- [x] 3.3 Access-mode binary: when NATS is configured, `SubscribeRisk` into the live RiskStore so continuous verification (D89) fires on real risk.

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test**: `ApplyRiskUpdate(marshaled RiskUpdate{subject, 0.9}, store)` → `store.Get(subject)` == 0.9; a malformed payload errors and does not set.
- [x] 4.2 **Test**: `PublishRisk` marshals a RiskUpdate a subscriber can decode (round-trip the bytes through ApplyRiskUpdate).

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D91: the risk-publish channel — server publishes per-subject risk (from peer-UEBA), the gateway subscribes and populates its RiskStore, so D89 continuous verification fires; T2 (server data, gateway decides); transport-secured (mTLS NATS, D55), per-message signing a follow-up.
- [x] 5.2 `openspec validate gateway-risk-publish --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| ApplyRiskUpdate does not Set the store | `TestApplyRiskUpdate` |
| ApplyRiskUpdate accepts an empty-subject update | `TestApplyRiskUpdateRejectsMalformed` |

THE VERDICT (D91): the server publishes per-subject risk (peer-UEBA), the gateway subscribes and
populates its RiskStore, so D89 continuous verification fires on real risk — T2 end to end (server data,
gateway decides). Transport-secured (mTLS NATS D55); per-message signing a follow-up. NOT in scope:
per-message risk signing, subject-space unification, posture producer, OIDC.
