## Why

The network plane (N1: a shared inspection/enforcement gateway) is the missing
half of a security PLATFORM — endpoint file-watching structurally cannot see the
primary exfil path, network egress. Before building the proxy data plane, we
settle the one thing everything hangs off: can the existing pipeline (Event →
Classify → Policy → Decision → Enforce → Audit) REPRESENT a network flow and a
network verdict without a rewrite? This is the D26 fitness test applied to the
network domain — and, like peer-UEBA (D53), the answer is proven IN CODE before
the capability is built. This change is the CONTRACT + fitness proof, NOT the
proxy.

## What Changes

- `NetworkSubject` — a flow/L7-request descriptor carrying connection/request
  METADATA ONLY (`flow_id` opaque handle into the gateway's live flow table = the
  enforce target; src/dst ip+port; protocol; sni_host; http_method; http_path;
  direction). Never the body content — the body is classified in the gateway
  PROCESS and never leaves it (D10/D29), exactly as file content stays in the
  worker. Added as a new `Event.oneof target` variant, mirroring how `usb` was
  added.
- `EventKind` gains `NETWORK_FLOW` and `HTTP_REQUEST`.
- `ACTION_REDIRECT` (send to a coaching/justification page) added to the closed
  Action set and to `validate.go`'s allowed-actions map.
- DELIBERATE minimalism: block-vs-reset is an enforcement MODE (drop vs RST — how
  the flow enforcer denies a flow), NOT a distinct policy verdict, so it stays in
  the enforcer/config and gets no action (keeps the Decision vocabulary small,
  D14). The flow enforcer REUSES the existing `core.TargetedEnforcer(ctx, dec,
  target)` with `target = flow_id` (the network analogue of a file path), so NO
  new enforcer interface is needed.
- A fitness test proves a network Event flows through the UNCHANGED dispatcher and
  is decided + audited, with a fake flow enforcer carrying out the verdict.

## Capabilities

### Modified Capabilities
- `event-contract`: an Event can describe a network flow / L7 request (metadata
  only), added as a target variant beside filesystem and usb.
- `decision-contract`: the closed action set gains `REDIRECT`; block-vs-reset is
  an enforcement mode, not a verdict.
- `architectural-fitness`: the network data plane is proven to need only small,
  identifiable additive core changes (a target variant + one action + one
  validator line) and ZERO dispatcher/enforcer-interface changes — the D26
  claim re-validated.

## Impact

- proto additions (regenerated), one line in `validate.go`, a fitness test. NO
  dispatcher, State, Stage, Registry, Enforcer-interface, OnOutcome, or ledger
  change.
- NOT built (stated plainly): the proxy data plane — TLS interception, the flow
  table, the network classifier, the flow-enforcer implementation, the telemetry
  projection. This change de-risks N1 by settling the contract first. Respects
  D10/D29 (Event carries metadata only), D14 (closed typed actions), D28 (typed,
  not map[string]any).
