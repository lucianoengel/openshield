# An operator's role was frozen for the life of their certificate

## Why

Named in the enterprise gap assessment as one of four gate items, and the only one of them that is a
**defect** rather than a missing integration.

Operator authorization was stamped into the client certificate's Subject OU at issuance (PLAT-3/D58) and
read from there on every request:

```go
if roleRank(certRole(r.TLS)) < min { ... }
```

So a demotion from responder to analyst, or removing someone's access entirely, did not take effect until
that certificate expired or the CA was rotated. **There was no "revoke this operator's responder rights
now" primitive at all.**

The enterprise checkbox this sat under is SSO. The checkbox is not the problem — the delay is. An
authorization change that lands on a certificate-lifetime schedule is exactly what an incident review finds
the hard way, because the operator whose access "was removed" still had it.

## What changes

The certificate keeps **authenticating** — CommonName says who. A new `operator_roles` table says what they
may do, **now**, and `requireTier` resolves against it per request.

- `openshield-server operator-role set|revoke|list` — an operator-local command, not a network route, for
  the same reason issuance and agent revocation are (D51): the ability to hand out admin must not be
  reachable over the network the console uses.
- Revocation is a **row**, not a delete.
- A database error **denies**; it does not fall back to the certificate.
- An identity with no row falls back to its certificate and is logged once, with the command that fixes it.
  `OPENSHIELD_OPERATOR_ROLES_STRICT=1` refuses that fallback.

## Impact

- Migration `039_operator_roles.sql`. No proto change, no new dependency.
- `requireTier` becomes a method on `Server`; every call site updated. `requireRole` is unchanged and now
  scoped to `agent`, which is not an operator tier.
- Affected capability: **operator-identity**.

## Design decisions worth stating

**No cache.** One primary-key lookup per authorized request. Caching would reintroduce exactly the
staleness this removes, with a shorter and less predictable window — "the revocation takes effect within the
cache TTL" is the sentence that makes a security control untrustworthy. The operator API is humans and
their tools, not the fleet.

**A database error denies.** Falling back to the certificate would turn an outage into a silent restoration
of stale privileges. Fail-open is right for the enforcement path (D17/D18) and wrong here, and the two are
not the same decision.

**Revocation is a row.** A delete would fall back to the certificate's embedded role, so "revoke" would
restore whatever the certificate said.

**`agent` is not grantable.** An agent certificate is a fleet credential on every endpoint; if one could
hold an operator tier, one compromised endpoint would be a compromised console.

## Honest limits

- **This is not SSO.** ZT-7 had two halves and this is the defect half. OIDC login for operators and SCIM
  deprovisioning are still absent, and the enterprise procurement gate is still open. What is closed is the
  ability to change or remove an operator's authority at all — which was worth doing on its own and is a
  prerequisite for the rest.
- **The fallback is not the end state.** Until a deployment sets strict mode, an operator with no row is
  still authorized by their certificate. That is a migration affordance with an announced exit, not a
  design.
- **No approval workflow on the grant itself.** `operator-role set admin` is one command by one person.
  Four-eyes exists elsewhere in this product (SOAR) and is not wired here.
- **Certificate revocation is still separate.** Revoking authorization does not invalidate the certificate;
  the identity can still authenticate, it just cannot do anything. Full credential revocation (CRL/short
  TTLs) is unchanged by this.
