# Tasks — network-flow Event/action contract + fitness proof

## 1. Proto additions

- [x] 1.1 `proto/openshield/v1/event.proto`: `NetworkSubject` (flow_id, src/dst ip+port, protocol, sni_host, http_method, http_path, direction enum), metadata only; add it as `Event.oneof target { ... NetworkSubject network = 11 }`; add `EVENT_KIND_NETWORK_FLOW` and `EVENT_KIND_HTTP_REQUEST`.
- [x] 1.2 `proto/openshield/v1/decision.proto`: `ACTION_REDIRECT = 6`.
- [x] 1.3 `make proto` (regenerate corev1); `proto-check` clean.

## 2. Core: allow the new verdict

- [x] 2.1 `internal/core/validate.go`: add `ACTION_REDIRECT` to the allowed-actions map (a REDIRECT decision must validate). NO other core change.

## 3. Fitness proof (guards, each mutation-tested)

- [x] 3.1 **Test**: a network Event (HTTP_REQUEST + NetworkSubject) runs through the EXISTING `core.Dispatcher` with a fake network-classify stage and a policy stage reading host/path → emits REDIRECT/BLOCK; assert the Decision is produced and audited via the existing OnOutcome sink. NO dispatcher/State/Stage/Registry change.
- [x] 3.2 **Test**: a fake flow enforcer implementing the EXISTING `core.TargetedEnforcer` carries out the verdict via `target = flow_id` (CanEnforce matches; EnforceTarget receives the flow_id).
- [x] 3.3 **Test**: `NetworkSubject` exposes no body/content field (metadata only, D10/D29); `ACTION_REDIRECT` validates and the vocabulary added no drop/reset verdict.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D69: the network data plane fits with a new Event target variant + one action + one validator line (mirroring USB) and ZERO dispatcher/enforcer-interface changes — D26 re-validated; state plainly what is NOT built (the proxy data plane).
- [x] 4.2 `openspec validate network-flow-contract --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| REDIRECT removed from the allowed action set | `TestNetworkEventFitsUnchangedDispatcher`, `TestNetworkContractBoundaries` |
| flow enforcer ignores the flow_id target | `TestNetworkEventFitsUnchangedDispatcher` |

Two EXISTING completeness guards also fired and were updated deliberately (as
designed): `TestActionEnumIsClosed` (the closed enum count) and the policy
action-name mapping — adding an action is never silent.

THE FITNESS VERDICT (D69): a network Event (HTTP_REQUEST + NetworkSubject) flows
through the UNCHANGED core.Dispatcher, is decided (REDIRECT/BLOCK reading the
network metadata) and audited via the existing OnOutcome sink, and the verdict is
carried out by the EXISTING core.TargetedEnforcer via target=flow_id. The network
data plane needed exactly: a new Event target variant + one closed action + one
validator line (mirroring how USB was added), and ZERO changes to the dispatcher,
State, Stage, Registry, enforcer interface, OnOutcome or ledger. The pipeline is
genuinely data-plane-agnostic. NOT built (stated): the proxy data plane — TLS
interception, flow table, network classifier, flow-enforcer implementation,
telemetry projection.
