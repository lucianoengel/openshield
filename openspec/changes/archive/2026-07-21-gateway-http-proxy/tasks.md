# Tasks — gateway HTTP forward-proxy connector (N1.2b)

## 1. Socket-backed flow table (internal/gateway.Table)

- [x] 1.1 `Table` implementing `flow.FlowTable`: `Register(flowID)` starts a flow at disposition=allow; `Block`/`Redirect` set the disposition and error if the flow_id is not registered; `Disposition(flowID)` reads it; `Deregister(flowID)` cleans up. Mutex-guarded for many in-flight flows. A `Disposition` type (allow|block|redirect).

## 2. Proxy handler (internal/gateway.Proxy)

- [x] 2.1 `Proxy` (http.Handler) holding the `*Gateway`, the `*Table`, an `http.RoundTripper` (upstream), a coaching `redirectURL`, and `maxBody`. Optional `enforce` — when set, register `flow.New(table)` on the Gateway (else observe-only, D1).
- [x] 2.2 `ServeHTTP`: mint flow_id; read body bounded by `maxBody` (buffered — classified AND forwarded; over-cap → 413, not truncated); register the flow (defer deregister); build a `gateway.Request` (flow_id, 5-tuple best-effort from RemoteAddr + the request URL, host/method/path, buffered body); call `gateway.Process`.
- [x] 2.3 On `Process` error: fail OPEN — forward with a high-severity log (the failure is already audited by the pipeline, D17/D18). Else read `table.Disposition`: allow → forward upstream via the RoundTripper and copy the response back; block → 403; redirect → 302 to `redirectURL`.

## 3. Binary (cmd/openshield-gateway)

- [x] 3.1 Thin main: config via env (listen addr, redirect URL, worker binary path, DSN, `OPENSHIELD_ENFORCE`); `StartWorker`; open the Postgres ledger; build Gateway (`NewFromWorker`) + Table + Proxy; `http.Server{Handler: proxy}` with graceful shutdown. Logs the plain-HTTP-only + observe-only posture.

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test**: REAL sockets, no Postgres (fake ledger). httptest upstream echo + `httptest.NewServer(proxy)` + a real `http.Client` using it as a PROXY. A clean body → FORWARDED (upstream received it, 200, body echoed).
- [x] 4.2 **Test**: a CPF body under a BLOCK-deciding policy with enforcement enabled → 403 and the upstream is NEVER hit.
- [x] 4.3 **Test**: a REDIRECT policy → 302 to the coaching URL, upstream never hit.
- [x] 4.4 **Test**: observe-only (enforcer NOT registered) with a BLOCK decision → FORWARDED and audited (D1).
- [x] 4.5 **Test**: a worker-error request → FAILS OPEN (forwarded) with the failure audited (D17).
- [x] 4.6 **Test**: `Table` unit — register→Block/Redirect sets the disposition; a verdict for an unregistered/deregistered flow errors; concurrent flows isolated (race-clean).
- [x] 4.7 **Test**: extend the dependency guard so `cmd/openshield-gateway` (as well as `internal/gateway`) does NOT link `internal/classify` (the network binary spawns the worker, D72).

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` D73: the HTTP forward-proxy connector + socket-backed flow table — the enforcer sets a per-flow disposition the owning handler applies to the live connection; observe-only default; fail-open on classify error (D17/D18); plain HTTP only, TLS interception + worker pool deferred.
- [ ] 5.2 `openspec validate gateway-http-proxy --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| block disposition forwards anyway (handler ignores block) | `TestProxyBlocksOnLiveConnection` |
| fail-open flipped to fail-closed (403 on pipeline error) | `TestProxyFailsOpenOnWorkerError` |
| flow table accepts a verdict for an unregistered flow | `TestTableRefusesUnregisteredFlow` |
| gateway/binary links the in-process parser | `TestGatewayDoesNotLinkTheParser` |

THE VERDICT (D73): the plain-HTTP forward-proxy connector runs each request through the D70
pipeline (body classified in the worker, D72) and applies the verdict to the LIVE connection —
forward / 403 / 302 — carried by a socket-backed flow table's per-flow disposition (the owning
handler applies it, no socket race). Observe-only by default (D1); fail-open on a pipeline
error, audited (D17/D18). Proven on REAL sockets (httptest upstream + proxy + real proxy
client), no Postgres. NOT in scope: TLS interception + do-not-intercept list (N1.3); the worker
POOL (throughput follow-up); active teardown of long-lived flows.
