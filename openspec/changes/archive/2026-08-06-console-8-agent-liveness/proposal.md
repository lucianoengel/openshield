# CONSOLE-8 increment 2 · The real agent's liveness

## Why

Two things turned up while scoping the roster's missing fields, and each is larger than the field it
blocked.

### 1. The only heartbeat producer in the tree is the SIMULATOR

`grep -rn "Heartbeat{" cmd/ internal/` returns exactly one non-test construction:
`cmd/openshield-fleet-agent/main.go:217`. That binary's own doc comment says what it is —

> Command openshield-fleet-agent is the fleet-facing half of an agent, **for the fleet simulation**
> (Direction 1). … It does NOT classify files or run the pipeline (that is the engine).

`openshield-engine` — the binary that actually watches files, classifies content, decides and enforces —
**never publishes a heartbeat.** Two shipped features therefore do not cover any real endpoint:

- **PLAT-9's enforcement acknowledgement.** `agent_enforcement` is written only by
  `recordEnforcementState`, which is called only from `recordHeartbeat`, which is fed only by the
  heartbeat subject. So on a deployment running engines, the table is **empty**, `FleetEnforcementState`
  returns zeros, the `/metrics` gauge reads zero, and D473's new roster reports `enforcement_disabled:
  null` for every host. "Did my fleet disable arrive?" — the question PLAT-9 exists to answer — is
  unanswerable on production.
- **The dead-man's-switch (T-018/D16).** `Overdue` advances last-seen from verified telemetry, and an
  idle engine on a quiet host publishes none. So a healthy idle endpoint is indistinguishable from a
  killed one — the exact false positive the heartbeat exists to prevent. `OverdueAgents`' own comment
  says the threshold "should be several heartbeat intervals", and for the engine there are none.

This is the same shape already found once **in this very file**: PLAT-2's comment reads *"Before this,
only the fleet SIMULATOR did — meaning every real detection this binary produced went over core NATS
at-most-once while the platform claimed durable ingest."* The simulator having a capability is not the
product having it.

### 2. `-X main.version` has stamped nothing, ever

`scripts/release.sh:29` builds every artifact with `-ldflags "-s -w -X main.version=$VERSION"`. **No
`cmd/*/main.go` declares a package-level `version`.** The Go linker silently ignores an `-X` target that
does not exist (verified directly), so every shipped binary carries no version and the flag has been
decorative since it was written.

That blocks the roster field it was needed for: reporting `agent_version: ""` would be the unwired-field
defect this repo has found six times.

## What Changes

- **`internal/buildinfo`** — one `Version` variable, stamped once. Not a `var version` per command:
  twelve places to forget is how this was missed, and a thirteenth binary would repeat it. `release.sh`
  stamps the package path; a guard test asserts the path in the script still resolves to the variable,
  so a package rename breaks the build rather than silently un-stamping the fleet.
- **`Heartbeat` gains `platform`, `agent_version`, `spool_depth`** (additive fields 6–8; no existing
  field changes meaning, and an old agent simply omits them).
- **`openshield-engine` publishes a signed heartbeat on an interval**, carrying its ACTUAL enforcement
  state from its own `KillSwitch` and the highest fleet-control sequence it has applied — so PLAT-9's
  acknowledgement and the dead-man's-switch finally describe the fleet rather than the simulation.
- **`agent_enforcement` gains the inventory columns**, projected from the same message at the same
  instant as the enforcement state, so the two cannot skew.
- **The roster serves them**, absent for an agent that has not reported them.

## Impact

- Affected specs: `heartbeat`, `enforcement`, `control-plane`, `packaging`.
- Affected code: `proto/openshield/v1/heartbeat.proto` (+ generated), new `internal/buildinfo`,
  `cmd/openshield-engine/main.go`, `internal/engine/engine.go` (an applied-sequence accessor),
  `internal/controlplane/heartbeat.go`, `internal/controlplane/fleet.go`, migration `052`,
  `scripts/release.sh`.
- **Proto change, and it is additive only.** No field is renumbered, retyped or removed, so a control
  plane at this version reads an old agent's heartbeat unchanged and an old control plane ignores the new
  fields. Nothing that is written into the hash-chained ledger changes — `Heartbeat` is liveness, not
  evidence.

## Deliberately NOT in this increment

- **Attestation verdict and posture** stay out for the reasons recorded in increment 1: attestation lives
  in the gateway's memory in another process, and posture is keyed by the pseudonymous subject (D23), so
  joining it to the agent roster would re-identify what the pseudonym protects.
- **The simulator keeps its own heartbeat.** It is what the fleet-simulation capability tests, and
  removing it would delete the coverage that found this.
