# Add the network enrollment endpoint (T-017 over the wire)

## Why

`Server.Enroll` binds an agent's key to its identity (D44), but it is an IN-PROCESS method — an
agent on a different host cannot call it. So enrollment cannot actually happen over the wire, which
means the whole signed-telemetry chain (D50) has no way to get an agent enrolled in a real
deployment. This adds the network endpoint an agent uses to enroll: it presents its single-use
token and public key, and the control plane records the identity.

## What changes

**An HTTP enrollment endpoint on the control plane.** `POST /enroll` with `{token, agent_id,
public_key}` (public key base64). The handler calls the existing `Enroll` (token verified, unused,
unexpired → identity recorded, token burned, D44) and returns 200 on success, 4xx on a bad or spent
token. A minimal `net/http` server, started alongside the NATS subscriptions.

**Token issuance stays an ADMIN-local operation, not a public endpoint.** `IssueToken` is NOT
exposed over the network: an unauthenticated "mint me a token" endpoint would let anyone enroll a
bogus agent. Tokens are issued by an operator (control-plane-local CLI / admin path) and handed to
an agent out of band; the agent uses the token ONCE at `/enroll`. This preserves the single-use
short-TTL model's whole point — a leaked endpoint cannot mint credentials.

**Errors are specific and safe.** A missing/expired/used token returns 401 with a generic message
(not "token expired" vs "token used" — that leaks nothing an attacker can use); a malformed body is
400. The endpoint records nothing sensitive in logs.

## What this does NOT claim or cover

- **No TLS in this change.** The endpoint is HTTP; the token travels in the body. The token is
  single-use and short-TTL, so interception has limited value, but production MUST front this with
  TLS — stated, and it is the same deployment concern T-017 named (mTLS/transport auth is
  complementary to the message-level identity this enables). Adding TLS is a deployment/config step,
  not application logic.
- **No token issuance over the network.** Deliberately — that would defeat the single-use model.
  Issuance is an admin operation.
- **No rate limiting or anti-enumeration beyond generic errors.** A brute-force of the token space
  is infeasible (32 random bytes), so rate limiting is a hardening nicety, noted not built.
- **It does not authenticate the operator issuing tokens.** Operator authn is the separate unbuilt
  gap (sibling of agent identity); token issuance assumes a trusted admin.

## Decisions

Depends on **D44** (per-agent identity, `Enroll`, single-use token), **D50** (the signed telemetry
this unblocks), and the environment/transport constraints.

No new architectural decision — it exposes the existing `Enroll` over HTTP. It records the
operational fact that enrollment is `POST /enroll` with a single-use token, that token ISSUANCE is
not a network endpoint (admin-only), and that production fronts the endpoint with TLS.
