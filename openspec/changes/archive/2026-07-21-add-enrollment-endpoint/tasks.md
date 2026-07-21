## 1. The endpoint

- [x] 1.1 `Server.EnrollHandler() http.Handler`: POST /enroll {token, agent_id, public_key(base64)}
      → Enroll; 200 success; 400 malformed/wrong-size key; 401 generic on ErrEnrollment; 500 else
- [x] 1.2 `Server.ServeHTTP(ctx, addr)` runs it with graceful shutdown; NO issuance route
- [x] 1.3 `cmd/openshield-server` starts it when OPENSHIELD_HTTP_ADDR is set

## 2. Tests

- [x] 2.1 **Test** (httptest + real Postgres): a valid token enrolls (200), the identity is
      recorded, and a signed message from the agent then verifies. `TestEnrollOverHTTP`
- [x] 2.2 **Test**: a spent/expired/unknown token → 401 generic (indistinguishable); a malformed
      body → 400; a wrong-size key → 400. `TestEnrollErrors`

## 3. Docs

- [x] 3.1 Note in `docs/decisions.md` (new D-number): POST /enroll single-use; issuance not exposed;
      generic errors; production fronts with TLS
- [x] 3.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| accept a wrong-size public key | `TestEnrollErrors` |
| return a specific per-token-state error | NOT catchable — indistinguishability is structural: `Enroll` returns ONE `ErrEnrollment` sentinel for unknown/expired/used, so no handler message can leak the state. `TestEnrollErrors` still asserts the property holds |

A valid token enrols over HTTP (200) and the agent's signed telemetry then
verifies (`TestEnrollOverHTTP`) — enroll-over-HTTP feeds the D50 chain. Spent/
expired/unknown tokens all return an identical 401 body; malformed body and
wrong-size key are 400 (`TestEnrollErrors`). httptest + real Postgres. Docs: D51.
