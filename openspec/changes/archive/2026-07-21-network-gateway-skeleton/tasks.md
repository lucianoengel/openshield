# Tasks — network gateway walking skeleton (N1.1)

## 1. Flow enforcer (internal/enforcers/flow)

- [x] 1.1 `FlowTable` interface: `Block(flowID string) error`, `Redirect(flowID string) error` — the seam a socket-backed table implements later (N1.2).
- [x] 1.2 `Enforcer` implementing `core.TargetedEnforcer`: `Capabilities()` = {ACTION_BLOCK, ACTION_REDIRECT}; `Enforce` (no target) errors ("flow enforcer needs a flow_id target"); `EnforceTarget(ctx, dec, flowID)` switches action → `table.Block`/`table.Redirect`, rejecting any other action and an empty target.

## 2. Gateway assembly (internal/gateway)

- [x] 2.1 `Request` type: flow_id, src/dst ip+port, protocol, host, method, path, direction, and `Body []byte` (the plaintext the gateway holds); `toEvent()` builds a `NetworkSubject` Event (metadata only, D69) with a fresh event_id, observed_at, and a one-way pseudonymised subject (D23).
- [x] 2.2 `Gateway` holding a `*classify.Classifier`, the policy stage, the ledger, a stage deadline, a logger, and registered enforcers (empty = observe-only, D1). `New(policy, ledger, logger, deadline)`.
- [x] 2.3 Body-classify stage: classify `req.Body` via `internal/classify`, build a CONTENT-FREE `LocalClassification` (type+confidence+count per hit occurrence, NO matched text — mirror the engine's projection, D10/D29), set `State.Classification`.
- [x] 2.4 `Process(ctx, req)`: build the Event; build a per-request `core.Dispatcher` with [body-classify stage, policy stage] and `OnOutcome = core.NewAuditSink(ledger).Record`; `Dispatch`; then `enforce()` the Decision. Return the Decision.
- [x] 2.5 `enforce()`: mirror `engine.enforce` — walk enforcers, `core.CanEnforce` gate, `EnforceTarget(ctx, dec, ev.GetNetwork().GetFlowId())`, audit the outcome (failure high-severity, never silent, D14); observe-only when no enforcer matches.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: a Request with a valid CPF in the body → `Process` → classify→policy→decision→audit lands an ALERT in a FAKE in-memory ledger (no sockets, no Postgres) with the REAL default policy; a capturing-stage test asserts the classification carried type+count only, no matched text.
- [x] 3.2 **Test**: with a flow enforcer registered and a policy deciding BLOCK, `Process` calls `FlowTable.Block(flow_id)` (fake table records the flow_id); a REDIRECT policy calls `FlowTable.Redirect(flow_id)`.
- [x] 3.3 **Test**: observe-only default — no enforcer registered, a BLOCK decision is recorded/audited but the fake table is never touched.
- [x] 3.4 **Test**: the flow enforcer rejects an action outside {BLOCK, REDIRECT}, errors without a flow_id target, and refuses `Enforce` (no target).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D70 (the network gateway walking skeleton reuses classify+dispatcher+policy+ledger+TargetedEnforcer, observe-only default, flow_id as the enforce target) and D71 (in-process body classification is a KNOWN gap — production must move it to the sandboxed worker, D29/D35). State plainly what is NOT built (sockets, socket-backed FlowTable, TLS interception).
- [x] 4.2 `openspec validate network-gateway-skeleton --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| body-classify attaches matched content (`MatchedText: "LEAK"`) | `TestNoBodyContentCrossesTheBoundary` |
| `enforce` passes an empty target instead of `flow_id` | `TestFlowEnforcerReceivesFlowID` (table touched 0 times) |
| flow enforcer routes REDIRECT to `Block` | `TestFlowEnforcerReceivesFlowID/redirect`, `TestEnforceTargetRoutesByAction` |
| flow enforcer accepts an unadvertised action | `TestEnforceTargetRejectsUnadvertisedAction` |

THE VERDICT (D70): a network request whose BODY carries a CPF flows classify (in-process,
body reused via `internal/classify`) → boundary-safe projection (type+count, no content,
D10/D29) → the UNCHANGED `core.Dispatcher` + REAL OPA policy → an audited ALERT in the
ledger; observe-only by default (D1); and a registered flow `Enforcer` carries BLOCK/REDIRECT
to a live flow via the EXISTING `core.TargetedEnforcer` with `target = flow_id`. New code:
`internal/gateway`, `internal/enforcers/flow`. ZERO change to the dispatcher, State, Stage,
Registry, the enforcer interface, OnOutcome, the ledger, or the proto. NOT built (stated):
real sockets + a socket-backed FlowTable (N1.2); TLS interception + do-not-intercept list
(N1.3). KNOWN GAP (D71): the body is classified IN-PROCESS — production must move it to the
sandboxed worker (D29/D35).
