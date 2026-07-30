# Operator SSO — the token authenticates, and deliberately does not authorize

## Why

ZT-7's second half. D372 fixed the defect (a role frozen for the life of a certificate); this closes the
enterprise procurement gate that sat on top of it. Enterprise IAM teams require SSO because what they are
buying is centralised joiner/mover/leaver, and "we issue you a client certificate" fails that regardless of
being cryptographically sound.

## What changes

An operator may present an OIDC bearer token instead of a client certificate. Both paths converge on the
same authorization: `operator_roles` decides, per request.

- `identity.OIDCVerifier.VerifySubject` — the existing ZTNA verifier gains a method returning the RAW
  subject, without requiring a role claim. `verifyCore` is extracted so signature, issuer, audience, expiry
  and not-before are shared with the ZTNA path rather than duplicated.
- `Server.SetOperatorOIDC`, `authenticateOperator` — a certificate or a bearer token, certificate first.
- Wired in `openshield-server` behind `OPENSHIELD_OPERATOR_OIDC_ISSUER`, with a live JWKS refresher so a
  key rotation needs no restart.

## The decision this rests on

**The token's claims do not decide the role.** Mapping an IdP group to a tier is the conventional design and
it reintroduces exactly what D372 removed: a token issued before a demotion still asserts the old group
until it expires. Shorter fuse than a certificate, identical failure. So the IdP is an identity provider
here and nothing more.

A consequence worth naming: an SSO operator has no certificate, so there is **no embedded role to fall back
to**. They are strict by construction — no record means no access, whatever the token claims. The legacy
fallback added in D372 exists for certificate holders only, and only until a deployment sets strict mode.

**The subject is not pseudonymised**, unlike the ZTNA path. D23 hashes a subject so the pipeline cannot
carry who a *monitored* person is. An operator is not the monitored population; they are staff acting on the
system, and "who revoked this agent" must have an answer.

**The certificate wins when both are present.** A request carrying both is ambiguous, and resolving toward
the credential the TLS stack verified — rather than one parsed from a header — is the conservative direction.

## Impact

- No new dependency, no proto change, no migration.
- `NewOIDCVerifierWithSource` now accepts an empty role claim, for a verifier used only via `VerifySubject`.
  The ZTNA path still requires one.
- Affected capability: **operator-identity**.

## Honest limits

- **SCIM is not implemented.** Deprovisioning is still a manual `operator-role revoke`. An IdP that
  deactivates a user does not automatically remove their OpenShield authority — though their tokens do stop
  being issued, which bounds the exposure to a token lifetime rather than indefinitely. This is the
  remaining half of the procurement gate and it is a REST API with its own schema, not a small addition.
- **No login flow.** This validates a bearer token; obtaining one is the caller's problem. That is the right
  shape for an API, and it means there is no browser session, no cookie and no CSRF surface — but it also
  means there is no console login until a UI exists.
- **No JIT provisioning.** A first-time SSO operator has no record and therefore no access until an admin
  grants one. That is deliberate given the decision above, and it is friction: a group-claim-to-record
  provisioning step (as opposed to group-claim-as-live-authorization) would be a defensible follow-up.
- **No four-eyes on a grant**, unchanged from D372.
- **Token replay is bounded only by expiry.** DPoP sender-constraining exists in this codebase for the ZTNA
  path and is NOT applied here; a stolen operator token is usable until it expires. Named rather than
  implied.
