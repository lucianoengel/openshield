# Design — CONSOLE-8 increment 2

## One stamped variable, not one per command

The obvious fix for `-X main.version` is to add `var version = "dev"` to each `cmd/*/main.go`. It is the
wrong one: `release.sh` builds twelve binaries, so that is twelve places to forget, and forgetting is
precisely how this shipped. A thirteenth command added next month repeats the bug silently, because a
missing `-X` target is a no-op rather than an error.

`internal/buildinfo.Version` is stamped once and every binary that imports anything reachable from it
gets the same value. The guard is a test that reads `scripts/release.sh`, extracts the `-X` target path,
and asserts it names a variable that actually exists in the tree — so renaming or moving the package
fails a test instead of quietly un-stamping the fleet.

`Version` defaults to `"dev"`, not `""`. An unstamped local build must be *identifiable as* an unstamped
local build, and an empty string in the roster reads as "we could not tell".

## The heartbeat carries the enforcement state the endpoint ACTUALLY has

The engine's heartbeat reads `KillSwitch.Engaged()`, not "what the last fleet control told us". This
matches the field's existing contract, which the migration comment already states: an agent disabled by
its LOCAL break-glass file reports `true` too, and that is information the control plane has no other way
to learn.

`applied_fleet_sequence` comes from the fleet-control subscriber's replay bound. It is legitimately zero
on an endpoint with no fleet-control channel configured (no broker URL, no control-plane key) — which is
a supported deployment, since `installKillSwitch` says so explicitly. Zero there means "has applied
nothing", which is true, and the roster reports it alongside `enforcement_disabled` so the two are read
together.

## Inventory goes in `agent_enforcement`, not a new table

Both facts are projected from the SAME message at the SAME instant. Two tables would create a skew state
that cannot occur in reality, and would make the roster join two projections that can each be
independently stale for no reason. One upsert, one `reported_at`, no possible disagreement.

The table keeps its name. It is referenced by a shipped metrics query and by D473's roster join, and
renaming it to `agent_self_report` would be churn that buys a better noun and nothing else. The migration
says what the table now means instead.

## The heartbeat interval, and why it is not the telemetry interval

A heartbeat is cheap and its whole value is bounding how long "gone" can go unnoticed, so it is its own
setting (`OPENSHIELD_HEARTBEAT_INTERVAL`, default 60s) rather than being folded into any existing loop.
`OverdueAgents`' threshold should be several of these; the default overdue threshold on `/overdue` is 15
minutes, which is fifteen intervals — enough that a reboot, a suspend or a brief outage does not cry
wolf, and short enough that a killed agent surfaces within a quarter of an hour.

A zero or negative interval disables the heartbeat and **says so at boot**. It must be possible to turn
off (an air-gapped endpoint with no broker has nowhere to send it), and a silently absent liveness signal
is the failure this whole increment is fixing — so turning it off is loud (D31).

## Failure to publish is logged, never fatal

The engine's job is to observe, classify and enforce. A broker that will not take a heartbeat must not
stop any of that — the spool already covers the outage for telemetry, and a heartbeat is worthless once
late, so it is not spooled. It is dropped and counted.

That is the opposite of the D473 fleet-control write, which aborts its publish. The distinction is the
same one both times: abort when the alternative is acting without a record; continue when the record is
the only thing at stake.

## Contradiction with the archived spec store

`openspec/specs/heartbeat/spec.md` describes the signal but does not name a producer, so nothing there is
contradicted. Requirements are ADDED, not modified.
