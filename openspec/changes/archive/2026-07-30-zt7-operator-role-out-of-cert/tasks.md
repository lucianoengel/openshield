# Tasks

- [x] Migration `039_operator_roles.sql` — identity, role, revoked, updated_at/by.
- [x] `resolveOperatorRole`: store first, revoked beats the certificate, DB error DENIES.
- [x] `requireTier` becomes a Server method; every call site updated; `requireRole` left for `agent`.
- [x] `SetOperatorRole` / `RevokeOperator` / `ListOperatorRoles`; revocation is a ROW.
- [x] `openshield-server operator-role set|revoke|list`, operator-local (D51).
- [x] Legacy fallback logged once per identity, with the fixing command; strict mode refuses it.
- [x] `agent` and unknown roles refused on the grant path.
- [x] Tests: demotion, revocation-beats-cert, revocation-is-a-row, legacy fallback, strict mode, closed set.
- [x] Mutation: resolving from the certificate first must fail the demotion/revocation/strict tests.
- [x] Map `EVENT_KIND_OBJECT_DISCOVERED` to a domain (caught by the enum-completeness guard).
- [x] `make quick` green; targeted package tests only.
