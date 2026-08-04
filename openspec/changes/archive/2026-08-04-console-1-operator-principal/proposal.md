# An SSO operator can read the queue and do nothing else, and fixing that naively breaks four-eyes

## Why

ZT-7 gave operators SSO (D373). It does not work for anything that attributes an action.

`requireTier` authenticates with a client certificate **or** an OIDC bearer token, resolves the role, and
then calls the handler — discarding `auth.identity`. It is never put on the request context. Eight
handlers derive identity independently from `operatorIdentity(r.TLS)`, which returns `""` when there is no
peer certificate, and every caller turns that into `401 client certificate required`.

So an operator authenticated by SSO passes the tier gate and is then refused by `/alerts/ack`,
`/incidents/ack`, `/incidents/transition`, `/incidents/timeline`, `/cases/*`, `/searches/save`, `/subject`
and `/view`. They can list incidents; they cannot acknowledge one, read its timeline, or touch a case.
D373 shipped an authentication method that reaches almost none of the product, and nothing said so — the
same shape as D415/D417/D418, where a counter was rendered by nothing.

**The obvious fix is a trap, and that is the real reason this is one change.** The two credential paths
mint different identity strings for the same human: a certificate yields `"operator:" + CommonName`, an
OIDC token yields the raw `sub`. Four-eyes is a string comparison inside the SQL predicate —
`AND requester <> $2`. Thread the bearer identity through unchanged and one person requests a case
closure, a `CONTAIN` intent, or a fleet `ENFORCEMENT_DISABLE` from the CLI as `operator:alice` and
approves it from a browser as `alice`. Two rows, two strings, predicate satisfied. Two-person control
collapses on the three most consequential acts in the product, and it collapses *quietly*, as a
side effect of a bug fix.

`docs/threat-model.md:143` grounds four-eyes in "the requester and the approver are taken from client
CERTIFICATES, never from a request field". Adding a second credential class without a canonical principal
removes the property that sentence describes.

This lands before PLAT-1 because the console cannot authenticate to the API without it — but it is not a
console feature. It is a defect in shipped SSO, and it is worth fixing whether or not a UI is ever built.

## What changes

**One canonical operator principal, namespaced by how it was proved.**

- `requireTier` places the authenticated principal on the request context; the eight handlers read it from
  there. `operatorIdentity(r.TLS)` stops being a handler-level entry point.
- A principal is namespaced: `cert:<CommonName>` or `oidc:<issuer>#<sub>`. The unprefixed forms are what
  allow an identity-provider subject to collide with a certificate CommonName, and `operator_roles` today
  keys on a bare string with no discriminator — so an IdP account named after an administrator's
  certificate inherits that administrator's row.
- An `operator_identities` table links principals to one account. **Four-eyes compares the account, not
  the principal string**, so the same human cannot approve their own request by changing credential.
- The operator route set becomes **data** — one table both the inner handler and the outer TLS mux iterate
  — because the existing guard against registered-but-unmounted routes is a hardcoded six-item list, and
  `/report/response` shipped unreachable past it. This change mounts it.

Three further seams ride along, because this is the only cheap moment for them. Each is small inside this
change and large after it: afterwards they mean touching the same eight handlers, the same pagination
cursors and the same four-eyes predicate a second time, and the second pass is the one this codebase's
history says ships a silent regression.

- **A machine principal** (`svc:<name>`) distinct from a human one, with its own issue/scope/expire/
  rotate/revoke lifecycle, and the rule that **a service account can never satisfy four-eyes**. Without it,
  a customer integrating a ticketing system hands a robot a human's certificate — which is precisely the
  confusion the account comparison is being built to detect.
- **A scope predicate on the principal**, resolved in `requireTier` and carried in the pagination cursor,
  defaulting to "all". This does not build multi-tenancy; it reserves the seam so tenancy is later a
  `WHERE` clause instead of a rewrite of every handler and cursor.
- **`admin` splits into `admin` and `privacy-officer`** for DSAR export, legal-hold release and the
  view-audit reader. One tier currently fuses "can change configuration" to "can read every subject's
  compiled personal data", and an access review cannot be answered with three tiers.

## The decision that shapes it

**Authorization does not move.** The role still comes from `operator_roles`, resolved per request,
uncached, revocation-wins. This change is about **attribution**, which is the half ZT-7 left behind: D372
made authority changeable, D373 made identity provable by two means, and nothing unified what those two
means *record*. A principal namespace is not cosmetic — it is what makes "the same human" a decidable
question, and four-eyes is arithmetic on that question.

## What this does NOT claim or cover

- It does **not** add a browser session, a cookie, or an OAuth client. Those are PLAT-1's `UI-1`. This
  change makes the existing bearer path work end to end; a session is a third credential built on the
  principal this change establishes.
- It does **not** make the console's credential sender-constrained. `OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP`
  continues to bind bearer tokens only.
- It does **not** repair the view audit. `/alerts`, `/search`, `/events`, `/logs`, `/incidents`,
  `/overdue`, `/subject` and `/searches/run` still record nothing, and that gap gets worse under a UI. It
  is a separate change in the same lane.
- It does **not** migrate historical `approvals` rows. Approvals already resolved keep the principal
  strings they were written with; the account comparison applies to pending and future rows. An operator
  who held both credentials before this change could have bypassed four-eyes, and no migration can
  retroactively detect it — that is stated, not fixed.

## Impact

- Affected capabilities: **operator-identity**, **control-plane**.
- One migration: `operator_identities`, plus an auth-method/issuer discriminator on `operator_roles`.
- No proto change. No new dependency.
- **BREAKING for deployments that granted a role to a bare OIDC subject**: those rows must be renamespaced
  to `oidc:<issuer>#<sub>`. The migration renamespaces existing rows and reports what it changed; an
  unrenamespaceable row denies rather than falling back, because a fallback here restores the collision
  the change exists to remove.
