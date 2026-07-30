# Removing an operator's access relied on somebody remembering

## Why

The last ZT-7 residual, and the other half of the enterprise procurement gate.

D372 made an operator's authority changeable and immediate; D373 gave them SSO; D379 made their tokens
unstealable. What was still manual is the thing enterprise IAM actually buys: when someone leaves, the
identity provider deactivates them **there** and every downstream system follows. Without it, OpenShield
relied on an administrator remembering to run `operator-role revoke` — and the gap between someone leaving
and someone revoking is precisely what an audit asks about.

## What changes

A SCIM 2.0 `/scim/v2/Users` endpoint covering the operations providers actually send: create, search by
`userName`, get, patch, replace, delete.

- **Deactivation revokes immediately**, on the credential the operator already holds, reusing D372's
  revocation — which is a row, not a deletion, because an absent record falls back to the certificate's
  embedded role and would restore the access the call exists to remove.
- **All four deactivation dialects work**: `{"path":"active","value":false}`, `{"value":{"active":false}}`,
  a PUT replace, and DELETE. Providers differ, and a deprovisioning that works against one and silently
  no-ops against another is worse than none, because it is believed.
- **Its own credential**, compared in constant time, and the endpoint is absent unless configured.

## The decision that shapes it

**Provisioning grants nothing.** A SCIM create records the identity with no role. That looks like an
omission and is the same call as D373's: the provider says who exists, this product says what they may do.
A create that granted a tier — from a group claim or a default — would put authorization back in the
credential path, which is the defect ZT-7 spent three changes removing.

So the honest summary: **this closes the LEAVER half of joiner/mover/leaver.** The joiner half still ends
with an administrator running `operator-role set`. That is a smaller claim than "SCIM support" usually
implies and it is the one the design supports.

## Impact

- No new dependency, no proto change, no migration (D372's table is reused).
- Affected capability: **operator-identity**.

## Honest limits

- **A subset of SCIM.** `userName` and `active`; the filter parser handles the one shape providers send
  (`userName eq "..."`) rather than SCIM's full grammar — building an expression evaluator that runs on
  outside input is surface this does not need. Groups, bulk operations, `/Me`, and the schema-discovery
  endpoints are absent, and a provider that requires `ServiceProviderConfig` may refuse to connect.
- **No group-to-role mapping**, deliberately, per the decision above.
- **Reactivation does not restore a role.** It clears the revocation; if no tier was granted since, the
  operator still has nothing. That is consistent and it will surprise someone.
- **No SCIM-side audit trail beyond the operator record's `updated_by`**, which reads `scim` rather than
  naming which provider or admin acted.
- This is untested against a real identity provider. The dialects covered come from the specification and
  from what providers are documented to send, not from an integration with one.
