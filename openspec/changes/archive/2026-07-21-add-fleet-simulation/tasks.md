## 1. Fleet agent + signed heartbeat

- [x] 1.1 Extend `SignedPublisher` with `PublishHeartbeat` (SignedTelemetry kind "heartbeat"); the
      control plane's handleSigned records last-seen for a verified heartbeat
- [x] 1.2 `cmd/openshield-fleet-agent`: generate identity → POST /enroll with the token → publish
      signed Heartbeat + signed Event on an interval
- [x] 1.3 `Containerfile.fleet-agent` (or reuse) building the fleet agent

## 2. Operator commands

- [x] 2.1 `openshield-server issue-token [ttlSeconds]` — connect Postgres, IssueToken, print it
- [x] 2.2 `openshield-server revoke <agent-id>` — Revoke the agent

## 3. Demo + assertions

- [x] 3.1 `deploy/fleet-e2e.sh`: up (enrollment endpoint + published ports) → mint N tokens via
      exec → run N agent containers → assert verified+attributed telemetry + last-seen → kill one →
      assert overdue → revoke one → assert its telemetry rejected → teardown + restore
- [x] 3.2 assertions via psql SQL (simpler than a Go checker) inside the script checker (or SQL) implementing the assertions against the published
      Postgres / control plane

## 4. Run it + docs

- [x] 4.1 Ran `deploy/fleet-e2e.sh` — PASSED live (see verification below) for real; record the result
- [x] 4.2 Note the fleet simulation in deploy/README.md; note fanotify perm mode is not simulable in
      rootless podman
- [x] 4.3 Validate; archive

## Verification performed

**Ran `deploy/fleet-e2e.sh` live and it PASSED:**

```
==> asserting verified+attributed telemetry from all 3 agents
   OK: 3 agents publishing verified, attributed telemetry
==> killing agent-1; expecting dead-man's-switch (overdue) after silence grows
   OK: agent-1 overdue (silent 6.33s), agent-2 alive (0.11s)
==> revoking agent-2; expecting its telemetry to be rejected
   OK: revoked agent-2 telemetry rejected (stale 5.44s), agent-3 still verified (0.21s)
FLEET SIMULATION PASSED
```

Three agent CONTAINERS each generated an identity, enrolled over HTTP with a
single-use token (issued via the operator-local `openshield-server issue-token`
run inside the control-plane container), and published verified signed telemetry
+ heartbeats. Killing agent-1 tripped the dead-man's-switch; revoking agent-2 (via
`openshield-server revoke`) got its telemetry rejected while agent-3 stayed
verified. Teardown ran and restored the dev Postgres. Fanotify permission mode
was probed and confirmed NOT simulable in rootless podman, recorded in the README.
