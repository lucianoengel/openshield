## Why

D56 gave the control plane AUTHENTICATED operator identity: the `/view` endpoint
records `operator:<CN>` from a verified mutual-TLS client certificate. But it is
authentication WITHOUT authorization. `/enroll` and `/view` are served by one TLS
config that trusts one CA, so ANY cert that CA issued — including an agent's
enrollment certificate — can call `/view`. An agent can read investigations; an
operator cert could enroll as a fake agent. The identity is verified, but nothing
checks what that identity is ALLOWED to do. D56 named this as a follow-up; this
closes it.

## What Changes

- A client certificate carries a ROLE in its Subject Organizational Unit (OU):
  `agent` or `operator`. Each route enforces the role it requires, layered on top
  of the existing mTLS authentication (D55/D56) — the role is read from the
  VERIFIED peer certificate, never from the request.
- `/view` requires role `operator`: an agent cert, or any cert without the
  operator role, is refused `403 Forbidden` — authenticated but not authorized.
- `/enroll` requires role `agent`: an operator cert cannot masquerade as an agent
  onboarding.
- The fleet-agent and both e2e scripts issue agent certs with `OU=agent` and
  operator certs with `OU=operator`. End to end: an operator cert can `/view` but
  not `/enroll`, and an agent cert can `/enroll` but not `/view`.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `operator-identity`: add authorization — a verified certificate is authorized
  per route by its role (OU), not merely authenticated, so agent and operator
  certs are no longer interchangeable.

## Impact

- New code: a small role helper (`certRole` from the peer cert OU) and a
  role-gate wrapper applied to `/view` (require operator) and `/enroll` (require
  agent). No change to the Decision contract or the mTLS layer itself.
- Affected: `internal/controlplane` (role gate + route wiring),
  `cmd/openshield-fleet-agent` docs/cert usage, `deploy/mtls-e2e.sh` + the
  operator flow (cert OU), docs (new D-number).
- SCOPE, stated honestly: authorization by a certificate ATTRIBUTE the CA sets —
  only as trustworthy as the CA's issuance discipline (a CA that signs
  `OU=operator` for the wrong party loses, the same class of trust as any PKI). A
  production system might prefer a dedicated policy OID over OU; noted as a
  refinement. D14 (observe-only) and D16 (host root defeats the key) hold. When
  TLS is off, the plaintext library paths are unchanged and `/view` still does
  not exist (D56).
