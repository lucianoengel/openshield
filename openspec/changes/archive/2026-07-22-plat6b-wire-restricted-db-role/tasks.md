# Tasks — PLAT-6b wire the restricted DB role
- [x] Migration 017: openshield_writer gets aggregate-table DML + default privileges (ledger stays constrained).
- [x] postgres.EnsureAppLogin (non-owner LOGIN member) + validRoleName.
- [x] postgres.MigrateIfNeeded; openshield-server `migrate` subcommand; server boot uses MigrateIfNeeded.
- [x] Real-adversary boundary test (app can write; cannot disable trigger even after RESET ROLE / cannot DELETE; owner-can contrast).
- [x] compose.yaml: migrate one-shot (owner) + server on the non-owner DSN.
- [x] systemd: openshield-migrate.service + app units repointed to the non-owner DSN, ordered after migrate.
- [x] e2e: observe-e2e runs the engine as the non-owner role (RAN, passed); fleet/mtls migrate-as-owner then run the server as non-owner.
- [x] Migration count test 16→17; make all clean.
- [x] docs D146; sync; archive; commit; push; memory.
