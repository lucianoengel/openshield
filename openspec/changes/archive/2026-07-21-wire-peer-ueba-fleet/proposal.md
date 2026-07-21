# Wire peer-UEBA into the fleet telemetry stream

## Why

peer-UEBA (D53) was built and proven — but only in a unit test with synthetic
subjects. Nothing in the running system computes peer baselines. Meanwhile the
control plane now receives VERIFIED telemetry from real agents (D50). The two
pieces do not touch.

This matters beyond tidiness: peer-UEBA is STATEFUL and CROSS-ENTITY — a subject
is risky only RELATIVE TO ITS PEERS. A single endpoint has no peers. So peer-UEBA
cannot run at the endpoint at all; its only real home is the control plane, where
the whole fleet's activity converges. Wiring it there is not an add-on — it is the
first place the capability can actually function.

## What changes

- The control plane gains an OPTIONAL peer-UEBA analyzer, **off by default** (D23
  consent/DPIA gate). When enabled, each VERIFIED `event` telemetry feeds the
  subject's pseudonymous id (D23) to the analyzer, which accumulates the
  cross-fleet baseline.
- When a subject's peer-relative risk crosses a threshold, the control plane
  records a **peer alert** — a server-side detection naming the subject, its risk
  score and the context version (D27). A rising-edge cooldown stops one anomalous
  subject from emitting an alert per event.
- This is OBSERVATION, not control (D14): the control plane produces an
  investigation; it does NOT feed risk back to agents or alter their behaviour.
  The endpoint policy-Context path proven in D53 stays the core seam; the running
  system uses peer-UEBA server-side.
- The live fleet e2e (`deploy/fleet-e2e.sh`) drives an outlier agent and asserts
  a peer alert is recorded for its subject while a typical subject produces none.

## Impact

- Affected specs: `control-plane` (MODIFIED: a new server-side analytics
  consumer), `peer-ueba` (ADDED: the fleet-stream integration and its D14 bound).
- Affected code: `internal/controlplane` (analyzer field, handleSigned hook,
  peer-alert record + cooldown, counter), a new migration for `peer_alerts`,
  `deploy/fleet-e2e.sh`, docs (D54).
- Off by default — no behaviour change unless explicitly enabled.
