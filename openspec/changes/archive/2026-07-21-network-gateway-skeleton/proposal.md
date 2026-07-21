## Why

D69 proved the pipeline can REPRESENT a network flow and verdict with only additive
contract changes. This change builds the first working piece of the proxy data
plane: the network-domain pipeline ASSEMBLY and a flow enforcer, proven end to end
WITHOUT sockets — the network analogue of the endpoint walking skeleton (D48/D62).
It mirrors exactly how the endpoint shipped: observe-first, contain-not-prevent,
inline blocking deferred (D1/D49). The gateway classifies a request body, runs it
through the EXISTING dispatcher + OPA policy, records a Decision to the forward-
secure ledger, and — only if a flow enforcer is registered — dispatches the verdict
to it. No real sockets, no TLS interception, no live-connection drop yet: those are
later increments. What ships is the reusable network pipeline and the enforcement
DISPATCH seam, both proven in tests.

## What Changes

- `internal/gateway` — a `Gateway` that, given a network `Request` (flow_id,
  src/dst, host/method/path, and the plaintext `Body` the gateway holds),
  classifies the BODY in-process by REUSING `internal/classify` (the existing
  CPF/Luhn/etc detectors run over the body bytes), builds a CONTENT-FREE
  boundary-safe classification (type + confidence + count; matched content NEVER
  attached — exactly as the engine projects worker hits, D10/D29), constructs a
  `NetworkSubject` Event (metadata only, D69), and runs it through the EXISTING
  `core.Dispatcher` (a body-classify stage + the OPA policy stage) with the
  EXISTING `NewAuditSink` for `OnOutcome` — the Decision lands in the ledger.
- Observe-only by DEFAULT (D1): with no flow enforcer registered the Gateway
  records the Decision and enforces nothing; registering one turns enforcement on
  per action.
- `internal/enforcers/flow` — a flow `Enforcer` implementing the EXISTING
  `core.TargetedEnforcer`, advertising `BLOCK` and `REDIRECT`, that resolves the
  `flow_id` target via a pluggable `FlowTable` interface (`Block`/`Redirect` by
  flow id). The socket-backed `FlowTable` is a later increment — this proves the
  enforcement DISPATCH with a table seam.
- The Gateway's `enforce()` dispatches a recorded Decision to a registered flow
  enforcer, passing `ev.GetNetwork().GetFlowId()` as the target (the network
  analogue of the engine passing the file path), auditing the outcome — failure is
  high-severity, never silent (D14).

## Capabilities

### Added Capabilities
- `network-gateway`: the network-domain pipeline assembly — classify a request body
  in-process (boundary-safe projection), decide via the existing pipeline, audit,
  and (observe-only by default) dispatch the verdict to a flow enforcer keyed by
  flow_id. Proven end to end without sockets.

### Modified Capabilities
- `enforcement`: a flow enforcer (BLOCK/REDIRECT) resolves a flow_id target through
  a pluggable flow table, reusing the existing `core.TargetedEnforcer` — the second
  domain (after files) to prove the target-string enforcer interface generalises.

## Impact

- New `internal/gateway` and `internal/enforcers/flow`; NO change to the
  dispatcher, State, Stage, Registry, the enforcer interface, OnOutcome, the
  ledger, or the proto. Reuses `internal/classify`, `internal/policy`,
  `core.NewAuditSink`.
- NOT built (stated plainly): real sockets + a socket-backed `FlowTable` that drops
  / resets / redirects a live TCP connection = N1.2; TLS interception + the
  do-not-intercept list = N1.3. And a real caveat carried forward, not hidden: the
  gateway classifies attacker-controlled network bodies IN-PROCESS here, whereas
  the endpoint sandboxes body parsing in the seccomp worker (D29/D35) — production
  body classification MUST move to a sandboxed worker (D71 hardening follow-up), not
  be assumed safe. Respects D10/D29, D14, D1/D49.
