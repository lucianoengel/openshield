# Tasks — authenticated operator identity for the view-audit

## 1. Authenticated view handler

- [x] 1.1 `internal/controlplane`: a view HTTP handler that reads the verified peer cert from `r.TLS`, derives `operator:<CN>`, refuses `401` with no view when no peer cert is present, and otherwise calls the existing `View` (record-before-return preserved).
- [x] 1.2 The handler serializes the returned telemetry rows to the response (event id + kind, boundary-safe — no content).
- [x] 1.3 Mount the route only under the TLS server config (a method like `ServeOperatorTLS` or extend the existing TLS mux), so it is absent when TLS is off.

## 2. Wire the server command

- [x] 2.1 `cmd/openshield-server`: when TLS is configured, serve the authenticated view route alongside enrollment on the TLS listener; when off, do not expose it.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: a view over mutual TLS records the viewer as `operator:<CN>` from the cert, ignoring any name in the request — asserted against the recorded `investigation_views` row.
- [x] 3.2 **Test**: a request without a client certificate is refused and records NO view (the handshake refusal under RequireAndVerifyClientCert, and defensively the nil-`r.TLS` path returns 401 with no row).
- [x] 3.3 **Test**: the recorded operator label is distinguishable from the legacy `unauthenticated:<os-user>` library path (both can be present; a query can tell them apart).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` new D-number: the view-audit viewer is now bound to a verified mutual-TLS cert (`operator:<CN>`), closing the self-asserted gap; authentication not authorization (agent-vs-operator cert roles are a follow-up); D14/D16 hold.
- [x] 4.2 `openspec validate add-operator-identity --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| take the viewer from a request param, not the cert | `TestAuthenticatedViewRecordsCertIdentity` |
| allow a view when the identity is empty (no refusal) | `TestViewWithoutCertRefused` |
| mount /view even without TLS | `TestViewRouteAbsentWithoutTLS` |

The view-audit viewer is now bound to a VERIFIED mutual-TLS client certificate
(`operator:<CN>`), not a caller-supplied string: a valid cert records the cert
identity (ignoring any request-supplied name), no verified cert is refused with
no view recorded, and the authenticated route exists only under mutual TLS. The
legacy library path stays explicitly `unauthenticated:<os-user>`, so the trail
distinguishes accountable views from self-asserted ones. This is AUTHENTICATION,
not authorization — any CA-issued cert authenticates as an operator; cert roles
(operator vs agent) are a follow-up.
