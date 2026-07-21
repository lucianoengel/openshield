## Why

SEC-1 (P0). The gateway's risk and posture channels decoded published updates with a bare
`proto.Unmarshal` and NO signature check — unlike the Ed25519-signed telemetry path. Anyone
able to publish to `openshield.v1.risk` / `openshield.v1.posture` (any enrolled agent, or
anyone past broker mTLS) could forge `risk=0` or `Compliant=true` for ANY subject — defeating
D89 continuous-verification step-up/deny AND the D85 device-posture tamper-lockout, i.e. the
security core of the one category (ZT) that actually works. This signs and verifies both
channels.

## What Changes

- Proto `SignedUpdate {payload, signature}` — an Ed25519-signed control-plane→gateway update.
- Gateway: `verifySignedUpdate` (verify-before-parse against a trusted key), `RiskSubscriber`
  and `PostureSubscriber` (verify each update, reject + COUNT the unverified via `Rejected`).
- Control plane: `Server.SetRiskSigner` + `PublishRisk` now SIGNS (and does not publish if
  unsigned). Server binary loads `OPENSHIELD_RISK_SIGNING_KEY`.
- Gateway binary: loads `OPENSHIELD_RISK_PUBKEY` / `OPENSHIELD_POSTURE_PUBKEY`; a channel with
  NO trusted key is NOT subscribed (never applies an unsigned update — fail-closed).
- `openshield-provision risk-keygen` emits the keypair.

## Capabilities

### Modified Capabilities
- `network-gateway`: the risk and posture channels are authenticated per-message.

## Impact

- Proto (regenerated); `internal/gateway/{signedupdate,risksub,posture}.go`,
  `internal/controlplane/{riskpub,controlplane}.go`, the server/gateway/provision binaries;
  `docs/decisions.md` D113.
- Proven: a control-plane-signed risk update is applied; a wrong-key (attacker `risk=0`),
  unsigned (raw RiskUpdate), empty-signature, tampered, or garbage update is REJECTED and the
  legitimate value stands (no forgery overwrites it); the same for posture (a wrong-key
  `Compliant=true` forgery for a new subject is rejected, the tamper-lockout holds). Guards
  mutation-tested: **"skip the signature check" fails the test** (the SEC-1 core); the
  key-length guard prevents a panic-DoS on a misconfigured key. The negative cases reach real
  Ed25519 verification, not a routing short-circuit.
- Scope: the RISK half is fully wired and happy-path tested. The POSTURE half verifies now
  (reject path tested), but its signed PRODUCER is HON-4 — until that lands the posture
  channel receives no valid update; what this fix guarantees is that an unsigned/forged
  posture update is REJECTED, closing the hole. Per-subject binding (a posture update's
  subject bound to the signing agent's identity) is the HON-4 refinement.
