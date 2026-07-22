## 1. Control-plane wiring (device side)

- [x] 1.1 Add `graph *xdr.Store` + `EntityResolveFailures atomic.Int64` to `Server`; build the store from the pool in `New`.
- [x] 1.2 Add a best-effort helper `resolveDevice(ctx, subject)` that calls `graph.Resolve(KindDevice, subject)`, swallowing+counting errors.
- [x] 1.3 Call `resolveDevice(pseudonym.Of(agentID))` after a successful `Enroll` commit.
- [x] 1.4 Call `resolveDevice(subject)` in `handleSigned` after a verified `event` is persisted.

## 2. Gateway wiring (device⋈user link)

- [x] 2.1 Add optional `graph *xdr.Store` + `SetEntityGraph` to `AccessProxy`.
- [x] 2.2 In `ServeHTTP`, when OIDC produced a user distinct from the device, fire an async best-effort `Link(KindDevice, deviceSubject, KindUser, userSubject)`.
- [x] 2.3 Construct the store from the pool and wire it in `cmd/openshield-server` and `cmd/openshield-gateway`.

## 3. Tests (drive the REAL path; mutation-verified)

- [x] 3.1 Test #1 (entity-join E2E): real `engine.SetSubject` → signed transport → `handleSigned`; assert `graph.Resolve(KindDevice, pseudonym.Of(A))` equals the id `Enroll` resolved — two real producers, one entity.
- [x] 3.2 Test: an ingest that persists still returns "persisted" and increments `EntityResolveFailures` when the graph write fails (best-effort).
- [x] 3.3 Test: the gateway links device⋈user for a dual-credential request (waitFor the async link), and the auth outcome is unchanged when the graph is absent.
- [x] 3.4 Mutation: removing the ingest resolve makes the two producers' ids diverge → 3.1 FAILs; removing the gateway link → 3.3 FAILs.

## 4. Gate + close

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`.
- [x] 4.2 `decisions.md` entry; sync the delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 4.3 Archive the change; commit with trailers; `git pull --rebase` + push; update memory + roadmap status.
