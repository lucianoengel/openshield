# Tasks — cert-role authorization on the mTLS surfaces

## 1. Role gate

- [x] 1.1 `internal/controlplane`: `certRole(state *tls.ConnectionState) string` — the first recognised role (`agent`/`operator`) in the verified peer cert's OU, else "".
- [x] 1.2 `requireRole(role string, h http.Handler) http.Handler`: `401` if no verified cert, `403` if the cert's role ≠ required, else serve `h`.

## 2. Wire the routes

- [x] 2.1 In `serve()` (TLS path), wrap `/view` with `requireRole("operator", ...)` and `/enroll` with `requireRole("agent", ...)`. Plaintext `/enroll` stays ungated (no cert, dev loop).

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: an `operator`-role cert can `/view`; an `agent`-role cert calling `/view` is `403` with no view recorded.
- [x] 3.2 **Test**: an `agent`-role cert can `/enroll`; an `operator`-role cert calling `/enroll` is `403` (no enrollment).
- [x] 3.3 **Test**: no cert → `401`, wrong role → `403` (the two outcomes are distinct); a cert with no recognised role is denied on both routes.

## 4. Certs & live e2e

- [x] 4.1 `deploy/mtls-e2e.sh`: issue the agent cert with `OU=agent` and add an operator cert with `OU=operator`; assert the operator cert can `/view` but not `/enroll`, and the agent cert can `/enroll` but not `/view`.
- [x] 4.2 `deploy/fleet-e2e.sh` is PLAINTEXT (no mTLS) so role gating does not apply — no change needed; roles are exercised in `mtls-e2e.sh` (4.1). Confirmed the plaintext fleet path is unaffected.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` new D-number: cert-role authorization closes the D56 hole (agent cert can no longer /view); role = Subject OU; 401 vs 403; trust rests on CA issuance (OU→policy-OID a refinement); D14/D16 hold.
- [x] 5.2 `openspec validate add-cert-role-authz --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| role gate ignores the role (always serve) | `TestViewRequiresOperatorRole` |
| /view mounted without the operator gate | `TestViewRequiresOperatorRole` |
| /enroll mounted without the agent gate | `TestEnrollRequiresAgentRole` |
| no-cert returns 403 not 401 (collapse the distinction) | `TestRoleGateOutcomesDistinct` |

Cert-role authorization closes the D56 hole: /view requires the operator role and
/enroll requires the agent role, read from the VERIFIED peer cert OU; wrong role →
403, no cert → 401 (distinct); deny-by-default for an unrecognised role. Existing
D55/D56 tests updated to carry roles. Proven live in mtls-e2e.sh (operator
/enroll=403, agent /view=403, operator /view=200).
