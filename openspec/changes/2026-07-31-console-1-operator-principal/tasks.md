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
- [ ] Guard test, grep-style in the `internal/doccheck` idiom: no handler outside the auth package reaches
  for `r.TLS` to derive an identity.
- [x] Test: a bearer-only operator acknowledges an incident, transitions it, reads its timeline, opens a
  case and saves a search — each attributed.
- [x] Mutation: revert the context threading → every bearer-path test must fail with 401.

## Four-eyes on the account

- [x] `operator_identities` migration linking principals to one account id; SCIM and `operator-role set`
  both write through it.
- [x] Approval predicate compares account id, not principal string.
- [x] Test: one human, two credentials, request + approve → refused, request stays pending.
- [ ] Test asserts the attempt **reached the tier gate** before the four-eyes refusal — a test that passes
  because the request never arrived is the INV-4 vacuous-negative trap.
- [x] Test: two distinct operators still satisfy four-eyes (the control must still permit the legitimate
  case).
- [x] Mutation: compare principal strings instead of account id → the self-approval test must fail.

## Seams that are cheap only here

- [ ] Machine principal kind `svc:<name>` with issue/scope/expire/rotate/revoke; expiry mandatory.
- [ ] Four-eyes refuses when either side is a machine principal.
- [ ] Test: a service account cannot approve; cannot request an approval-gated act; an expired credential
  authenticates nothing.
- [ ] Mutation: allow a machine principal to approve → the refusal test must fail.
- [ ] Scope predicate on the principal, resolved in `requireTier`, carried in the pagination cursor,
  defaulting to "all". No tenancy behaviour yet — only the seam and its default.
- [ ] Test: the default scope changes no existing result set (this is the guard that the seam is inert).
- [ ] Split `admin` into `admin` + `privacy-officer`; DSAR export, legal-hold release and the view-audit
  reader move to the latter. Migration grants existing admins both, and reports it.
- [ ] Test: a configuration-only admin cannot export subject data; a privacy officer cannot change config.
- [ ] Mutation: collapse the two tiers back → both separation tests must fail.

## Route set as data

- [ ] `var operatorRoutes = []route{{Pattern, MinTier, Handler}}`; both the inner handler and the outer
  TLS mux iterate it.
- [ ] Mount `/report/response` (SOAR-6) — registered at `operator_read.go:231`, absent from the outer mux.
- [ ] Replace the hardcoded six-path list in `operator_routes_test.go` with iteration over the declaration:
  every route is served with a credential, refused without one.
- [ ] Mutation: delete an entry from the outer loop → the served-route test must fail.

## Close

- [x] Update `docs/threat-model.md` — the four-eyes boundary currently says the requester and approver are
  taken from client certificates; state the account comparison and the unmigratable-history residual.
- [ ] `go test ./internal/controlplane/ ./internal/store/postgres/` and `make quick`. Targeted only.
- [ ] `openspec archive` with spec sync.
