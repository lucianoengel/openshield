# Design

## One JWT validator, not two

The tempting implementation is a fresh verifier in the control plane — the ZTNA one returns the wrong shape
(a pseudonymised subject and a required role claim), so copying it is a small diff.

It is also how a check goes missing. Signature, issuer, audience, expiry, not-before and a present subject
are six fail-closed checks, and a second copy is a second place for one of them to be dropped or to drift
when the first is fixed. So `verifyCore` is extracted and both paths use it; the difference between them is
what happens AFTER validation, which is exactly the part that legitimately differs.

## What differs after validation, and why

| | ZTNA subject (`Verify`) | Operator (`VerifySubject`) |
| --- | --- | --- |
| Subject | pseudonymised (D23) | raw |
| Role | from the configured claim | from `operator_roles` |

**The subject.** D23 hashes a subject so the pipeline cannot carry who a monitored person is. An operator is
not the monitored population — hashing here would make "who revoked this agent" unanswerable, and an
unattributable action is not evidence.

**The role.** This is the whole point of the change. A group claim is authorization travelling inside a
credential, which is the defect D372 removed from certificates. A token's shorter lifetime makes it less bad
and not different in kind: a demotion still does not apply until the token expires.

## No fallback for a token, and that is a feature

`resolveOperatorRole` falls back to the certificate's embedded role when an identity has no record — the
migration affordance from D372. A bearer-authenticated operator has no certificate, so there is nothing to
fall back to and the code says so explicitly rather than reaching for a default.

The result is that SSO operators are strict from day one while certificate holders migrate. That asymmetry
is deliberate and worth keeping: the fallback exists to avoid locking an existing deployment out of its own
control plane, and a brand-new SSO identity has no such history to protect.

## Failing loudly on a half-configured provider

An issuer with no audience or no key source is a startup failure. The alternative — falling back to
certificates-only — means a deployment that believes SSO is enabled has it silently off, and finds out from
whoever cannot log in. A misconfiguration should fail where somebody is watching.

## The mutation

Giving a bearer-authenticated operator with no record a default tier — i.e. letting the token alone
authorize — fails `TestAnSsoOperatorIsAuthorizedByTheServerNotTheToken`. That is the property the whole
design exists for, so it is the one that has to be falsifiable.
