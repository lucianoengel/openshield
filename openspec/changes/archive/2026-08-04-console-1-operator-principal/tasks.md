# Tasks

> **Deviation from the written design, recorded rather than silently taken.** The plan called for
> "auth-method + issuer columns on `operator_roles`". The namespaced key already encodes both, so
> separate columns would be a second source of truth for the same fact — the drift this repo keeps
> paying for. The stated acceptance is unchanged and met: an IdP subject equal to a certificate
> CommonName gets no role, and the same subject from a second issuer is a different operator.
>
> **The migration renamespaces nothing, and that is a finding, not a shortcut.** Grants were stored
> under a BARE identity (`certIdentity` returned the CommonName unprefixed for the role lookup while
> `operatorIdentity` returned `operator:<CN>` for the audit trail; SCIM stored the raw `userName` in the
> same column). A bare row does not record which credential class it was for, so renamespacing it means
> guessing — and either guess grants access to the wrong credential. Legacy rows are left denying and
> the migration RAISEs a notice with the count. **Re-granting every operator is required on upgrade.**

## Principal

- [x] `operatorPrincipal` type: namespaced (`cert:<CN>`, `oidc:<iss>#<sub>`), one constructor per credential
  path, no bare-string construction outside it.
- [x] `authenticateOperator` returns the namespaced principal; `resolveOperatorRole` keys on it.
- [x] Migration: auth-method + issuer columns on `operator_roles`; renamespace existing rows and report the
  count changed; a row that cannot be renamespaced is left denying, not defaulted.
- [x] Test: an identity-provider subject equal to a certificate CommonName gets no role.
- [x] Test: the same subject from a second issuer is a different operator.
- [x] Mutation: strip the namespace before lookup → the collision test must fail.

## Identity reaches the handlers

- [x] `requireTier` puts the principal on the request context; add the accessor and make it the only read
  path.
- [x] Replace the eight `operatorIdentity(r.TLS)` call sites (`alert_ack.go:55`, `cases_http.go:66`,
  `dsar.go:115`, `incidents.go:175`, `savedsearch.go:233`, `soar2.go:147`, `timeline.go:186`,
  `views.go:186`) with the context read; a missing principal refuses.
- [x] Guard test, grep-style in the `internal/doccheck` idiom: no handler outside the auth package reaches
  for `r.TLS` to derive an identity.
- [x] Test: a bearer-only operator acknowledges an incident, transitions it, reads its timeline, opens a
  case and saves a search — each attributed.
- [x] Mutation: revert the context threading → every bearer-path test must fail with 401.

## Four-eyes on the account

- [x] `operator_identities` migration linking principals to one account id; SCIM and `operator-role set`
  both write through it.
- [x] Approval predicate compares account id, not principal string.
- [x] Test: one human, two credentials, request + approve → refused, request stays pending.
- [x] Test asserts the attempt **reached the tier gate** before the four-eyes refusal — a test that passes
  because the request never arrived is the INV-4 vacuous-negative trap.
- [x] Test: two distinct operators still satisfy four-eyes (the control must still permit the legitimate
  case).
- [x] Mutation: compare principal strings instead of account id → the self-approval test must fail.

## Seams that are cheap only here

- [x] Machine principal kind `svc:<name>` with issue/scope/expire/rotate/revoke; expiry mandatory.
- [x] Four-eyes refuses when either side is a machine principal.
- [x] Test: a service account cannot approve; cannot request an approval-gated act; an expired credential
  authenticates nothing.
- [x] Mutation: allow a machine principal to approve → the refusal test must fail.
> **Deviation, recorded and argued rather than silently taken. The scope seam is NOT built.**
>
> Half of it is unimplementable today: there is no pagination cursor to carry a scope in. `CONSOLE-6`
> (keyset pagination) has not started — `maxSearchLimit = 1000` with no cursor and no `has_more` — so
> "carried in the pagination cursor" describes a thing that does not exist.
>
> The other half buys nothing. **The seam is already here:** `requireGrant` puts the authenticated
> principal on the request context, and any scope is a function of that principal, derivable at the
> moment tenancy is designed from the value already threaded. A field that always says "all", plus a test
> asserting it changes nothing, is unwired code by construction — and this repo has now found that shape
> five times (D313, D415, D417, D418, and `Views`/`ViewsBy` in D470). The expensive part of tenancy is
> deciding what a scope MEANS and enforcing it in every query; a constant does not make that cheaper.
>
> **What IS cheap only now is the requirement, and it is recorded on CONSOLE-6 instead:** a pagination
> cursor must never be a bearer of authorization. A cursor that encodes a position and is honoured
> without re-deriving the caller's scope lets one operator replay another's cursor and page through rows
> they were never entitled to — a defect that is nearly free to prevent while the cursor is being
> designed, and expensive once clients hold cursors.

- [x] ~~Scope predicate on the principal, carried in the pagination cursor, defaulting to "all"~~ — not
  built; see the deviation above. The requirement moved to `CONSOLE-6`.
- [x] ~~Test: the default scope changes no existing result set~~ — there is no seam to guard.
- [x] Split `admin` into `admin` + `privacy-officer`; DSAR export, legal-hold release and the view-audit
  reader move to the latter. Migration grants existing admins both, and reports it.
- [x] Test: a configuration-only admin cannot export subject data; a privacy officer cannot change config.
- [x] Mutation: collapse the two tiers back → both separation tests must fail.

## Route set as data

> **Deviation, recorded.** A GUARD rather than a shared table. Restructuring how 37 security-gated routes
> are mounted risks landing one at the wrong TIER, which is worse than the drift it would prevent — and
> the tier is already declared exactly once, in the outer mux, so there was no duplication to remove
> there. `TestEveryRegisteredOperatorRouteIsMountedAndViceVersa` fails when the two sets diverge, in
> either direction. Measured: 37/37, no divergence; `/report/response` IS mounted, so the ticket's claim
> that it was not is **stale**.

- [x] ~~`var operatorRoutes = []route{{Pattern, MinTier, Handler}}`~~ — replaced by the closure guard
  above; see the deviation note.
- [x] Mount `/report/response` (SOAR-6) — registered at `operator_read.go:231`, absent from the outer mux.
- [x] Replace the hardcoded six-path list in `operator_routes_test.go` with iteration over the declaration:
  every route is served with a credential, refused without one.
- [x] Mutation: delete an entry from the outer loop → the served-route test must fail.

## Close

- [x] Update `docs/threat-model.md` — the four-eyes boundary currently says the requester and approver are
  taken from client certificates; state the account comparison and the unmigratable-history residual.
- [x] `go test ./internal/controlplane/ ./internal/store/postgres/` and `make quick`. Targeted only.
- [x] `openspec archive` with spec sync.
