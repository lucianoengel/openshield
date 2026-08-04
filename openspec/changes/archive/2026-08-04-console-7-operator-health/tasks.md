# Tasks

- [x] `HealthReport` gathering leadership, broker state, ingest repairs, database reachability, schema
  skew and the last anchor. Nothing cached — a cached health surface reports the moment it was last
  convenient rather than now.
- [x] `problems` names the consequence of each fault, not the field it came from.
- [x] `degraded` is DERIVED from `problems` and cannot disagree with it.
- [x] `GET /health` mounted at the analyst tier; registered and mounted (the closure guard covers both).
- [x] `SetLeaderHeld` called from the election in `cmd/openshield-server`, and cleared when leadership is
  lost — a stale `leader: true` on a demoted process is worse than no field, because it is the answer an
  operator would act on.
- [x] Test: a follower is not reported as degraded.
- [x] Test: the gathered facts are non-zero, so an all-zero report cannot pass as healthy.
- [x] Test: an unanchored ledger is reported rather than assumed fine.
- [x] Test: `problems` serializes as `[]`, never `null`.
- [x] Integration: the report is reachable at operator tier from the SHIPPED binary, and its `leader:
  true` comes from the real election — a package test cannot prove `SetLeaderHeld` is ever called.
- [x] Mutation: leadership counted as a problem → the follower test fails.
- [x] Mutation: the anchor branch dropped → the anchor test fails.
- [x] Mutation: the route registration dropped → 404.
- [x] Mutation: the binary never records leadership → the integration test fails naming the unwired field.
