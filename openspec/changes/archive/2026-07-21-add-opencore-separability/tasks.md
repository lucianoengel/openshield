## 1. The boundary check

- [x] 1.1 `scripts/check-opencore-boundary.sh`: for every open package (`go list ./...` excluding
      `internal/enterprise/...`), fail if any dependency is under `internal/enterprise`
- [x] 1.2 A `--selftest` mode: in a temp module, plant an open→enterprise import and assert the
      detection logic flags it, so the check is proven to fire with nothing real to guard yet
- [x] 1.3 Reserve the namespace: `internal/enterprise/README.md` stating the one-way rule

## 2. Wiring + docs

- [x] 2.1 Run the check (and its `--selftest`) in the `invariants` CI job
- [x] 2.2 Mark T-021 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| detection made to never flag an enterprise dep | `--selftest` fails: "the check did NOT flag an open->enterprise import" |

The real tree is clean (`check` passes), and `--selftest` plants an open→enterprise
import in a temp module and asserts the check fires — so the guard is proven to work
before it has anything real to guard, which is the whole point of drawing the line
now (D21). Both run in CI. The reserved namespace is documented in
`internal/enterprise/README.md`, which states the one-way rule.
