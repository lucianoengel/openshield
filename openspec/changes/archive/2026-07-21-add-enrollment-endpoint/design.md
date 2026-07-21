## Context

`Server.Enroll(ctx, token, agentID, pub, now)` and `IssueToken` exist (D44). No network surface.
The control plane already runs (NATS subscriptions + Postgres). net/http is stdlib.

## Goals / Non-Goals

**Goals:**
- `POST /enroll` calls Enroll; 200 on success, safe generic errors otherwise.
- Token issuance stays admin-local (NOT a network endpoint).
- An http.Handler testable with httptest, plus a Serve helper.

**Non-Goals:**
- TLS (deployment); token issuance over the wire; rate limiting; operator authn.

## Decisions

### POST /enroll, JSON body
Request `{ "token": "...", "agent_id": "...", "public_key": "<base64 std>" }`. The handler decodes,
base64-decodes the key, checks it is `ed25519.PublicKeySize`, and calls `Enroll`. Responses:
- 200 `{ "enrolled": true }`;
- 400 for a malformed body or wrong-size key;
- 401 `{ "error": "enrollment refused" }` for `ErrEnrollment` — GENERIC, so it does not reveal
  whether the token was unknown, expired or used (leaking that aids an attacker probing tokens);
- 500 for an unexpected error.

### The handler is an http.Handler on the Server
`Server.EnrollHandler() http.Handler` returns a mux with `/enroll`. `Server.ServeHTTP(ctx, addr)`
runs it with graceful shutdown on ctx cancel. `cmd/openshield-server` starts it alongside Run when
`OPENSHIELD_HTTP_ADDR` is set.

### Token issuance is not exposed
No `/issue-token` route. Issuance is an operator action via a control-plane-local path (a small
`openshieldctl`-style admin command or direct method); the design records this so the omission is a
decision, not an oversight.

### Testable with httptest
Tests drive `EnrollHandler` with `httptest` (no real socket): a valid token enrolls (200) and the
identity is recorded; a spent/expired token → 401 generic; a malformed body → 400; a wrong-size key
→ 400. Then a signed-telemetry message from the enrolled agent verifies — proving enroll-over-HTTP
feeds the D50 chain.

## Risks / Trade-offs

- **HTTP, not HTTPS.** The token is single-use short-TTL, limiting interception value; production MUST
  add TLS. Stated on the endpoint and in docs; it is a config step, not logic.
- **Generic 401** trades debuggability for not leaking token state. The right trade for a credential
  endpoint; the operator sees specifics server-side if they enable debug logging (which must not log
  the token).
- **No issuance endpoint** means token distribution is an out-of-band operator step. Deliberate — the
  alternative reopens the shared-secret / mint-at-will risk A6 flagged.
