## 1. Sign + verify a timestamped payload

- [x] 1.1 `Sign(secret []byte, ts int64, body []byte) string` signs `strconv(ts) + "." + body`
      (keep `"sha256="+hex`). Add `TimestampHeader = "X-Openshield-Timestamp"` and an exported
      `ReplayTolerance = 5 * time.Minute`.
- [x] 1.2 `VerifySignature(secret, body []byte, tsHeader, sigHeader string, now time.Time, tolerance time.Duration) bool`:
      parse `tsHeader` (fail → false); reject `abs(now.Unix()-ts) > tolerance`; else recompute and
      constant-time compare.

## 2. Webhook sends both headers

- [x] 2.1 `Webhook` gets `now func() time.Time` (default `time.Now`, set in `NewWebhook`). In `Notify`,
      when a secret is set, stamp `ts := w.now().Unix()`, set `X-Openshield-Timestamp` + the signature
      over `(ts, body)`. No secret → no headers, body unchanged (preserved).

## 3. Verify + mutation guards

- [x] 3.1 Test (frozen clock): a fresh signed delivery verifies; a tampered body / wrong secret fails;
      a delivery whose timestamp is older than the tolerance is REJECTED even though the body-HMAC matches
      (the replay case); a far-future timestamp is rejected.
- [x] 3.2 Test: the real `Webhook.Notify` sets both headers over the timestamped body and a receiver
      using `VerifySignature` accepts it; with no secret, neither header is present.
- [x] 3.3 Mutation guards (apply, FAIL, revert): (A) drop the freshness check → the stale-replay test
      FAILs (it would verify); (B) sign only `body` (omit the timestamp) → the tamper/verify test still
      passes but the sender/receiver payloads diverge — assert the timestamped verify FAILs on a
      body-only signature. Record it. (Confirmed 2026-07-22: (A) disable the freshness check → the stale-replay assertion FAILs; (B) MAC over body only → the different-timestamp signature verifies → the timestamp-binding assertion FAILs; both reverted.)

## 4. Gate + record

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 4.2 decisions.md entry (next D-number).
- [x] 4.3 Roadmap + memory updated.
