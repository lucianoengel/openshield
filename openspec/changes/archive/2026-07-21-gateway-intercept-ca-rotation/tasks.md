# Tasks — interception CA rotation (D79)

## 1. CertMinter.Rotate + named TTL

- [x] 1.1 Extract the leaf validity into a named const (`leafTTL`, ~24h) with the revocation-posture comment (short TTL = leaf revocation; no CRL needed).
- [x] 1.2 `Rotate(caCertPEM, caKeyPEM)` — parse+validate the new CA (reuse the NewCertMinter parsing); on success, under the mutex, swap caCert/caKey/caDER and CLEAR the cache; on invalid PEM, return an error and leave the active CA and cache untouched (fail-safe).

## 2. Binary

- [x] 2.1 `cmd/openshield-gateway`: register a SIGHUP handler that reloads the interception CA files and calls `minter.Rotate`; a reload error is logged and the old CA keeps serving. (Only when interception is enabled.)

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: mint a leaf for a host under CA1 (verifies against CA1); `Rotate` to CA2; mint for the SAME host → the new leaf chains to CA2 and NO LONGER verifies against CA1 (cache flushed + new CA).
- [x] 3.2 **Test**: `Rotate` with invalid PEM returns an error and the minter still mints a valid leaf under CA1 (fail-safe).
- [x] 3.3 **Test**: `Rotate` concurrent with `For` is race-safe (run under `-race`).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D79: the interception CA is hot-rotatable (validate → atomic swap → flush cache, fail-safe, SIGHUP reload); leaf revocation is the short leaf TTL; CA revocation is rotate-away or remove-to-tunnel; endpoint trust-store removal is the endpoint's job.
- [x] 4.2 `openspec validate gateway-intercept-ca-rotation --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| Rotate does not flush the leaf cache | `TestRotateSwapsCAAndFlushesCache` (stale leaf verifies against CA1) |
| Rotate swaps before validating (not fail-safe) | `TestRotateFailSafeOnInvalidCA` |

THE VERDICT (D79): the interception CA is hot-rotatable — validate → atomic swap → flush cache,
fail-safe on a bad rotation, SIGHUP reload; leaf revocation is the short leaf TTL (no CRL needed), CA
revocation is rotate-away or remove-to-tunnel, endpoint trust-store removal is the endpoint's job. NOT
in scope: CRL/OCSP; automated scheduling; endpoint trust distribution; gateway-side multi-CA overlap.
