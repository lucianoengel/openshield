# Tasks — SEC-1 sign & verify risk/posture channels (D113)

## 1. Sign + verify

- [x] 1.1 Proto SignedUpdate; gateway verifySignedUpdate + RiskSubscriber/PostureSubscriber (verify-before-parse, Rejected counter); controlplane SetRiskSigner + PublishRisk signs; binaries wire keys (RISK_PUBKEY/POSTURE_PUBKEY/RISK_SIGNING_KEY, fail-closed); provision risk-keygen.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: signed risk/posture applied; wrong-key/unsigned/empty-sig/tampered/garbage rejected + legit value stands; bad-length key errors (no panic). Mutation "skip signature check" fails; "drop key-length guard" fails.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D113.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| signature verification skipped | a wrong-key/forged risk update is then applied |
| trusted-key length guard removed | a misconfigured key panics instead of erroring |
| (empty-signature guard removed) | SURVIVES — ed25519.Verify returns false on empty sig; honest defense in depth |
