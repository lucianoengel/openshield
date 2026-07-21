## Context

Under mutual TLS (D55), `serve()` mounts `/enroll` always and `/view` only when
TLS is on. Both run behind one `RequireAndVerifyClientCert` server config, so by
the time a handler runs the peer certificate is CA-verified. D56 reads the CN for
the operator identity; this reads the ROLE (OU) for authorization. A single
listener with one CA is kept — the role attribute, not a separate trust root,
distinguishes agent from operator.

## Goals / Non-Goals

**Goals:**
- `/view` is callable only by an `operator`-role cert; `/enroll` only by an
  `agent`-role cert.
- The role comes from the verified peer certificate, never the request.
- A wrong-role but authenticated cert gets `403` (distinct from the `401` for no
  cert) — the trail can tell "not authenticated" from "not authorized".

**Non-Goals:**
- A full RBAC / policy engine, multiple operator tiers, or per-investigation ACLs
  — two roles, per-route.
- Certificate issuance / a PKI (a CA sets the OU out of band; the e2e generates
  throwaway certs with the right OU).
- Changing the mTLS layer, the Decision contract, or the plaintext dev paths.

## Decisions

**Role = Subject OU, one of `agent` / `operator`.** OU is standard, openssl-
settable (`/OU=operator`), and human-readable in the trail. `certRole` returns the
first OU that matches a known role, or "" (unknown → authorized for nothing). A
cert may carry only one recognised role; extra OUs are ignored.

**A role-gate wrapper, not per-handler checks.** `requireRole(role, h)` wraps a
handler: it reads the verified peer cert, computes the role, and serves `h` only
if the role matches — else `403` (wrong role) or `401` (no verified cert). `/view`
= `requireRole("operator", ViewHandler)`, `/enroll` = `requireRole("agent",
EnrollHandler)`. Keeping the gate separate keeps each handler unaware of authz and
makes the rule one line per route.

**403 vs 401.** No verified certificate → `401` (unauthenticated); a verified
certificate with the wrong role → `403` (authenticated, not authorized). The
distinction is real and worth surfacing: it is the difference between "you are
nobody" and "you are somebody, but not allowed here".

**Enrollment now requires the agent role.** Previously any cert (or none, in
plaintext) could enroll. Under TLS, `/enroll` now demands an `agent`-role cert —
so an operator credential cannot spin up a fake agent. The single-use token
remains the second factor; the role is the first gate. In PLAINTEXT (no TLS)
there is no cert and no role, so enrollment is unchanged (dev loop); the role gate
only applies to the TLS-served routes.

## Risks / Trade-offs

- **Trust rests on CA issuance.** The role is an attribute the CA signs; a CA that
  issues `OU=operator` to the wrong party defeats it. This is the same trust
  class as any PKI and is stated plainly — the win is that role is now CHECKED,
  not that the CA is infallible.
- **OU is semantically overloaded.** "Organizational Unit" is not literally "role".
  It is a pragmatic, widely-used carrier; a production deployment might use a
  dedicated policy OID or a custom extension. Noted as a refinement, not required
  here.
- **A cert with no recognised role is locked out of both routes.** That is the
  safe default (deny), but it means existing agent certs without an OU must be
  reissued with `OU=agent` to keep enrolling under TLS. The e2e and fleet-agent
  cert generation are updated accordingly; documented for operators.
