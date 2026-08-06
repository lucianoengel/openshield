# One implementation of the replay answer

## Why

**Retroactive change for D479 (`d12bd78`), written to repair a workflow gap: it shipped without one.**

CONSOLE-10 asks for replay + explain over HTTP. **Neither half is buildable on the control plane**, and
the reason is architectural rather than effort:

- **The ledger is endpoint-local.** `cmd/openshield-server/main.go:6` states it — the hash-chained record
  is *"the agent's local forward-secure ledger, NOT this aggregate."* The control plane holds the
  PROJECTED decision in `fleet_telemetry`, which is the same proto but not the tamper-evident record.
- **The policy is endpoint-local.** `policy.SelectFromEnv` reads the SERVER's `OPENSHIELD_POLICY_*`.
  Endpoints deliberately do not read the configuration store, and delivering configuration to them is
  `PLAT-5c`, which is open.

A control-plane `/replay` would therefore re-evaluate under the server's policy and compare against an
endpoint's decision. On any fleet not configured identically to its server, **"DIVERGED" is the normal
result** — a route that cries wolf until operators stop reading it, which is worse than no route.

The **explain** half is blocked on the same `decision.proto` question as `CONSOLE-40`, now the second
ticket that question caps: `selectWinner` returns a candidate carrying `name`, the `Decision` is built
with `PolicyId: s.id` (the composite's), so `win.name` is discarded.

## What Changes

- `cli.ReplayResultFor` returns the comparison as a structure; `Replay` becomes a renderer over it.
- The caveat travels IN the result rather than in each renderer.
- No route is added.

## Impact

- Affected specs: `audit-timeline`.
- No behaviour change: the pre-existing replay tests pass unchanged.
