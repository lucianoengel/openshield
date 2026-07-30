# Tasks

- [x] `scripts/coverage-integration.sh` — instrumented build of `./cmd/...`, run the suite through
  `OPENSHIELD_INTEGRATION_BIN_DIR` + `GOCOVERDIR`, report per-package coverage ascending plus the
  unreachable set. Refuse to report when zero profiles were collected or the parse yields no rows.
- [x] `scripts/check-cmd-closure.sh` — the fast guard. Fail on an unexplained package outside the
  `./cmd/...` closure, and on a stale allowlist entry. Nine entries, each with a category reason;
  the platform-gated one names its importing file.
- [x] Mutation-verify the guard both directions: a throwaway unimported package must fail it, and a
  typo'd allowlist entry must fail it as stale.
- [x] Wire the guard into `make quick` and `make check`.
- [x] Wire the guard into the CI `invariants` job, with the rationale in the step comment.
- [x] Run the measurement and record the numbers — total, per-package work list, and any suite
  failures observed under instrumentation (reported as observed, not explained away).
- [x] `docs/enterprise-gap-assessment.md` — the feature-gap assessment against a top-tier enterprise
  baseline, every OpenShield-side claim verified against the tree at `HEAD`.
- [x] `docs/unwired-audit.md` — Round 46: the closure result, the coverage numbers, and the
  `filewatch`/Windows finding.
- [x] Roadmap: record the measurement and the guard; correct the `fleet-simulation` overstatement.
- [x] `make quick` green.
