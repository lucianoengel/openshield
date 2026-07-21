# Tasks — client-cert identity producer (D86)

## 1. Client-role issuance (provision)

- [x] 1.1 `provision.RoleClient = "client"`; `IssueClientCert(caCertPEM, caKeyPEM, identity, group string) (certPEM, keyPEM []byte, err error)` — Ed25519 leaf, CN=identity, OU=[RoleClient], O=[group], ExtKeyUsage clientAuth, signed by the CA. `IssueCert` unchanged.

## 2. Identity producer (internal/gateway/identity)

- [x] 2.1 `type Identity struct { Subject string; Role string }`; `FromClientCert(leaf *x509.Certificate) (*Identity, error)` — require OU contains RoleClient (else reject); Subject = "sub_"+hash(CN) (one-way, D23); Role = O[0] (the group).
- [x] 2.2 `Identity.Context() *core.Context` — Context{Identity: Subject, Role: Role}, DevicePosture.HasPosture=false.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test** (real certs): `IssueClientCert("alice@corp","finance")` → `FromClientCert` yields a PSEUDONYMOUS subject (assert "alice@corp" does NOT appear in Subject) and Role "finance".
- [x] 3.2 **Test**: an agent-role and an operator-role cert are REJECTED by `FromClientCert`.
- [x] 3.3 **Test**: `Identity.Context()` has Identity set, Role "finance", and `DevicePosture.HasPosture == false` (fail-closed until the posture producer runs, D85).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D86: the client-cert identity producer — RoleClient issuance + FromClientCert resolves a verified, pseudonymised subject + group role into core.Context (D85), replacing the sha256(src-IP) non-identity; posture separate so unattested devices still fail closed; OIDC a follow-up.
- [x] 4.2 `openspec validate gateway-identity-producer --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| FromClientCert skips the client-role check | `TestFromClientCertRejectsNonClient` (wrong-reason assertion) |
| the raw identity is not pseudonymised | `TestFromClientCertResolvesPseudonymousSubject` (leak) |
| Context() forces HasPosture present | `TestContextLeavesPostureAbsent` |

THE VERDICT (D86): a distinct RoleClient issuance path + FromClientCert verifies a client cert against
the CA (D60) and resolves a verified, one-way-pseudonymised subject (D23) + authorization-group role
into core.Context (D85) — replacing the sha256(src-IP) non-identity (D84); posture stays a separate
producer so unattested devices fail closed. NOT in scope: OIDC (A.2b), access-proxy mode (§5.1),
posture producer, service catalog (§5.4), risk loop (§5.5).
