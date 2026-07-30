# Design

## Identity is slow, authorization is fast — and they were the same field

The certificate answered both questions. That is fine for identity, which changes when someone joins or
leaves, and wrong for authorization, which changes when someone moves team, goes on leave, or is walked out
of the building. Binding the fast-changing answer to the slow-changing credential is what froze it.

Splitting them is the ordinary shape of every system that got this right, and the split is what makes the
change immediate rather than the storage technology.

## Why `requireTier` became a method and `requireRole` did not

`requireTier` gates the operator tiers, which are now administered, so it needs the Server to reach the
store. `requireRole` gates `agent` exactly — a property of the credential the fleet was issued, not a grant
somebody administers — so it still reads the certificate, and `validOperatorRole` refuses `agent` on the
grant path so the two families cannot be mixed.

Keeping `requireRole` unchanged also keeps the enroll route's behaviour identical, which matters because
every agent in the fleet depends on it.

## The three ways this could have been made unsafe

1. **A cache.** Rejected. The property being bought is immediacy; a TTL sells it back.
2. **Falling back to the certificate on a database error.** Rejected. It converts an outage into a silent
   privilege restoration. This project fails open on ENFORCEMENT (D17/D18) because a wedged endpoint is
   worse than a missed detection; it must not fail open on AUTHORIZATION, where the analogous reasoning does
   not hold.
3. **Revocation as a delete.** Rejected, and this is the subtle one — an absent row falls back to the
   certificate, so deleting to revoke would RESTORE the embedded role. A test pins it, because the failure
   is invisible until the moment it matters.

## The migration, and why the fallback has an announced exit

Every operator certificate already issued carries a role. Store-only authorization in one step locks every
existing deployment out of its own control plane, including whoever would fix it.

So: no row → the certificate decides, and the server logs it ONCE per identity with the exact command to
record the role server-side. Once every operator has a row, `OPENSHIELD_OPERATOR_ROLES_STRICT=1` refuses
certificate-embedded roles entirely.

Once per identity, not per request: a warning that repeats on every request is one people filter, and a
filtered warning is the same as no warning.

## What the mutation proved

Restoring the defect — resolve from the certificate first — fails the demotion test, the revocation test and
the strict-mode test. Every one of those cases presents the SAME certificate throughout, which is
deliberate: if they could be satisfied by issuing a new certificate they would be testing issuance rather
than the thing that was broken.

## A guard caught the omission this change would have shipped

Adding `EVENT_KIND_OBJECT_DISCOVERED` in the previous change left it unmapped to an XDR domain, and
`TestUnifiedDomainMappingIsEnumComplete` failed with "has no domain — extend unifiedDomainFor when adding an
EventKind". Discovery maps to DLP: the domain names which detection plane saw it, and a sweep is the same
content classification reaching the same policy, differing only in that it went looking. Giving it its own
domain would split one data-security picture on a distinction about how the bytes arrived.
