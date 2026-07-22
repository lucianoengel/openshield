## Why

SEC-10 (P2). The peer-UEBA context-version counter is in-memory and resets to 0 on restart, so
a version string ("ctx-N") from one run COLLIDES with the same N from another run — two
different populations sharing a context_version, which breaks D27's attribution of WHICH
context a Decision saw. This persists a monotonic version base across restarts.

## What Changes

- Migration `014_peerueba_version.sql`: a single-row `peerueba_version` counter.
- `peerueba.WithStartVersion(base)` seeds the counter; `Server.reserveVersionBase` reserves a
  monotonic BLOCK per startup (the ledger-sequence reservation pattern, D66); `EnablePeerUEBA`
  seeds the analyzer with the reserved base.

## Capabilities

### Modified Capabilities
- `peer-ueba`: the context version is monotonic and non-colliding across restarts.

## Impact

- New migration, `internal/analytics/peerueba/peerueba.go`, `internal/controlplane/controlplane.go`;
  `docs/decisions.md` D126.
- Proven: (peerueba unit) two analyzers seeded with different bases never produce the same
  context_version for the same activity, while the same base is deterministic (a control against
  a false pass); (Postgres) two "startups" reserve disjoint version blocks so their versions
  differ across a restart. Guards mutation-tested (don't-reserve/start-at-0 → collision;
  WithStartVersion-ignores-base → collision).
- NOT in scope (stated, the SEC-10 remainder): persisting notification dedup (`notifiedOverdue`)
  and the peer-alert cooldown (`peerLastAlert`) so a restart does not re-page — a follow-up
  (they degrade gracefully: at most one duplicate page per restart); persisting the peer-UEBA
  BASELINES (they self-heal by re-learning after a restart, so losing them is degradation, not
  a correctness bug like the version collision this fixes).
