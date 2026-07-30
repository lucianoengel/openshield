# Tasks

- [x] `/scim/v2/Users`: create, search by userName, get, patch, replace, delete.
- [x] Deactivation → immediate revocation, as a ROW (a delete would restore the certificate's role).
- [x] Accept all four deactivation dialects; an unrecognised patch is 200, not 400.
- [x] Its own constant-time token; 404 when unconfigured; not behind the operator tiers.
- [x] `recordOperatorIdentity` — provisioning records an identity and grants NO role.
- [x] Tests: deactivation removes access on a held credential; every dialect; provisioning grants nothing;
  an operator certificate cannot reach it.
- [x] Mutations: delete-instead-of-revoke, provisioning-grants-a-tier, any-token-accepted — all must fail.
- [x] `make quick` green; targeted package tests only.
