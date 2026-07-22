## 1. Role tiers + requireTier

- [x] 1.1 Add role constants `RoleAnalyst`/`RoleResponder`/`RoleAdmin`; a `roleRank(role)` (analyst=1,
      responder=2, admin=3, legacy operator=3, agent/unknown=0); `certRole` recognizes all five OUs.
- [x] 1.2 Add `requireTier(minRole, h)`: 401 without a verified cert, 403 when `roleRank(certRole) <
      roleRank(minRole)`, else serve. Keep `requireRole` for the exact-`agent` case.

## 2. Per-route gating

- [x] 2.1 `/enroll` → `requireRole(RoleAgent)` (unchanged); `/view` → `requireTier(RoleAdmin)`.
- [x] 2.2 The operator read handler baseline → `requireTier(RoleAnalyst)`; inside it wrap `/alerts/ack`
      and `/incidents/ack` with `requireTier(RoleResponder)`.

## 3. Provisioning accepts the new roles

- [x] 3.1 `IssueCert`: accept `analyst`/`responder`/`admin` in addition to `agent`/`operator` (reject
      anything else). Reference the shared role constants.

## 4. Verify + mutation guards

- [x] 4.1 Test (real role gate, provisioned/synthetic certs): an analyst cert reads the queue but is
      403 on ack and on /view; a responder acks (200) but is 403 on /view; an admin (and a legacy
      operator) cert is served on read, ack, and /view; an agent cert is 403 on every operator route
      and 200 on /enroll; no cert → 401.
- [x] 4.2 Test: `roleRank` ordering (analyst<responder<admin, operator=admin, agent/unknown=0);
      `IssueCert` accepts the new roles and rejects an unknown one.
- [x] 4.3 Mutation guards (apply, FAIL, revert): (A) make `requireTier` an exact match (`==` instead of
      `>=` rank) → the "admin acks / admin views" or "responder covers analyst" assertion FAILs;
      (B) drop the responder gate on `/alerts/ack` → the "analyst is 403 on ack" assertion FAILs. Record it. (Confirmed 2026-07-22: (A) requireTier == instead of >= → analyst gate rejects responder/admin → FAIL; (B) /alerts/ack gate lowered to analyst → analyst ack reaches the handler (400 not 403) → FAIL; both reverted.)

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 5.2 decisions.md entry (next D-number); note OIDC-group backing + org multi-tenancy deferred.
- [x] 5.3 Roadmap + memory updated.
