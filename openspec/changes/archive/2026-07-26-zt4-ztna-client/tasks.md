## 1. The broker client

- [x] 1.1 `internal/ztna`: a `Client` that serves an HTTP proxy on LOOPBACK ONLY and forwards each request
  to the access proxy over mTLS with the device certificate, attaching the configured bearer token.
- [x] 1.2 Refuse construction without a device certificate; never fall back to a direct connection or an
  unauthenticated retry.

## 2. Tests against the REAL access proxy

- [x] 2.1 End-to-end: real upstream service + real `gateway.AccessProxy` (device cert + policy) + real ztna
  client. An authorized device's request reaches the upstream and the response returns.
- [x] 2.2 A refused device: the request fails, the broker's reason is surfaced, and the upstream is NOT
  reached. **Mutation:** fall back to a direct connection on refusal → the upstream IS reached → FAILS.
- [x] 2.3 No device identity → no listener, clear error.
- [x] 2.4 The listener binds loopback only. **Mutation:** bind 0.0.0.0 → FAILS.

## 3. Wire and land

- [x] 3.1 A client mode/binary using the enrolled identity; document that it brokers, and does not yet
  prevent, bypass.
- [x] 3.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; roadmap + decision register; commit `ZT-4`, sync
  spec, archive.
