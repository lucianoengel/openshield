## Why

A unix socket address is bounded by the kernel — 108 bytes on Linux, 104 on macOS — and the kernel does
not truncate an over-long one. It refuses the bind with `EINVAL`, which surfaces as `bind: invalid
argument`: a message naming neither the length nor the cause.

D324 fixed that for the test suite after it took the macOS CI job down for a day. The PRODUCT has the
same exposure and no guard at all. An operator who configures `OPENSHIELD_EXEC_IPC_SOCKET` under a long
path — a per-tenant directory, a container mount, an operator's home — gets a process that starts,
validates its configuration, announces the feature ACTIVE, and then fails to listen for a reason that
reads as a broken socket. For the exec gate that is the worst shape: the engine's verdict server never
comes up, and the privileged gate silently degrades to its static path with an audited fail-open on every
exec. Nothing in that chain says "your path is too long".

The configuration layer is the right place to catch it. It already refuses a path whose parent does not
exist; the length is the same class of check, knowable before anything binds, and reportable against the
field the operator got wrong.

## What Changes

- **A new `KindSocketPath`.** A socket path is validated like an output path — the product creates it, so
  only the parent must exist — AND bounded by the platform's unix address limit.
- **This reverses a D321 decision, deliberately.** D321 declined to add a socket kind because it would
  have behaved identically to `KindOutputPath`, and a kind that differs from another only in name is
  noise. That reasoning was right then and does not hold now: the two kinds now differ in behaviour, and
  a behavioural difference is exactly what justifies a distinct kind.
- **The limit is the running platform's**, not a portable minimum: 108 on Linux, 104 elsewhere. Rejecting
  a 106-byte path on Linux, where it binds correctly, would be refusing valid configuration — which is
  its own defect, and a worse one than the message being slightly platform-specific.
- **The fitness guard tightens**: a setting whose key ends in `_SOCKET` must be `KindSocketPath`.
- The four socket settings are redeclared.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `typed-config`: the configuration model gains a socket-path kind whose validation includes the
  platform's unix address limit.

## Impact

- `internal/config` — one new kind, one validation branch, a platform constant behind build tags, four
  redeclared fields.
- `internal/fitness` — the `_SOCKET` guard now requires the new kind.
- No runtime behaviour changes for a correctly-configured deployment: every existing valid value stays
  valid. A deployment whose socket path is ALREADY too long moves from an unexplained runtime failure to
  a refusal at startup that names the field — louder, and earlier.
