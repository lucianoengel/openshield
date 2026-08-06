# Tasks — CONSOLE-8 increment 1

- [x] 1. Migration `051_fleet_controls.sql` — `control_id` PK, `verb`, `sequence` (unique), `issued_at`,
      `expires_at`, `reason`. Index for "the standing control" (`sequence DESC`). No `suppressed` column
      and no `issued_by` column; both are argued in `design.md`.
- [x] 2. Record the control in `PublishFleetControlSeq`, after the four-eyes gate and before
      `conn.Publish`, with a write failure aborting the publish.
- [x] 3. `internal/controlplane/fleet.go` — `FleetControlRecord`, `FleetControls(ctx)` joining `approvals`
      for the requester/approver/assurance pair, and `FleetSuppression(ctx, now)` deriving the standing
      control by sequence.
- [x] 4. `FleetRoster(ctx, now)` — the roster query over `agent_identities` LEFT JOIN verified
      `fleet_telemetry` LEFT JOIN `agent_enforcement`, with never-seen and never-reported both absent
      rather than zero-valued.
- [x] 5. `GET /fleet` and `GET /fleet/controls` handlers on the operator read mux; mount both at analyst
      tier in `enroll_http.go`.
- [x] 6. Package tests, each with its stated mutation:
      - a refused disable leaves no record (mutation: record before the gate → fails)
      - a lapsed TTL ends suppression (mutation: store a flag / ignore expiry → fails)
      - a later RESTORE supersedes a standing DISABLE (mutation: order by `issued_at` → fails)
      - sequence beats wall-clock under skew (mutation: order by `issued_at` → fails)
      - a disable reports its four-eyes pair; a restore reports absence, not `""`
      - never-seen serializes as `null`, never-reported enforcement as unknown
      - the routes are refused without a credential
- [x] 7. Integration test against the shipped binary: publish a real approved disable through
      `openshield-server fleet-control`, then read `/fleet/controls` over HTTPS and see it standing with
      its pair. The register's only writer is reachable from `cmd/`, so a package test cannot prove it
      wired.
- [x] 8. Route-closure guard stays green (the two new routes must be mounted, not merely registered).
- [x] 9. Docs: `docs/decisions.md` D-number row; `docs/architecture-roadmap.md` CONSOLE-8 status and the
      increment-2 scope (heartbeat platform/version/spool-depth) recorded on the ticket.
