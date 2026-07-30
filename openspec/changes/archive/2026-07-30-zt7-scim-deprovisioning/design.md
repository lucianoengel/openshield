# Design

## Why deprovisioning is nearly all of it

SCIM is usually sold as provisioning. Here the provisioning half is deliberately inert, so what remains is
the leaver flow — and that is the half with a security consequence. A user who should have lost access and
has not is a live credential; a user who has not yet been granted access is an inconvenience.

That asymmetry is worth being explicit about, because "SCIM support" invites the reader to assume the joiner
flow works end to end. It does not, and the spec says so.

## Revocation, not deletion — again

D372 made this call for the CLI and it matters more here, because a provisioning API is where "delete the
user" is the natural verb. An absent row falls back to the role in the operator's certificate, so deleting
would RESTORE what the provider just tried to remove. `DELETE /Users/{id}` therefore revokes.

The mutation for this is direct: making deactivation delete the row instead fails the scenario.

## Accepting every dialect

Providers send deactivation four ways. Handling one and ignoring the rest produces the failure mode this
project keeps finding — something that looks configured, reports success, and does nothing. So the patch
handler accepts both value shapes, and PUT and DELETE are wired to the same operation.

A patch that changes nothing this understands returns 200 rather than 400: a provider syncing a display name
must not get an error and start retrying forever.

## Its own credential

The endpoint can remove an administrator's access. Reaching it with an operator credential would let an
analyst deactivate an admin — privilege escalation through a provisioning API, which is a well-trodden way
to lose a console. So it is not behind the operator tiers at all; it authenticates with a dedicated token,
constant-time compared, and returns 404 when unconfigured rather than existing unauthenticated.

## The filter parser is deliberately not one

SCIM's filter grammar is large. Providers use exactly one shape before creating a user —
`userName eq "value"` — so that is what is parsed. Implementing the grammar would mean an expression
evaluator running on input from outside the trust boundary, which is surface bought for nothing.
