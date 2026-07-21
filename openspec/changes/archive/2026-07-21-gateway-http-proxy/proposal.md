## Why

D70 built the network gateway pipeline and D72 moved body classification into the
sandboxed worker, but the gateway still has no data plane — nothing accepts a real
connection. This change is the connector: a plain-HTTP forward proxy that accepts a
live connection, runs the request through the gateway pipeline, and carries the
verdict back to that connection (forward, block, or redirect). It is the network
analogue of the fanotify connector (D62) — the piece that turns the assembled
pipeline into something that sees real traffic.

## What Changes

- `internal/gateway.Table` — a socket-backed `FlowTable` (the existing
  `enforcers/flow.FlowTable` interface). Instead of manipulating a socket directly
  it records a per-flow DISPOSITION (allow | block | redirect) that the owning
  connection handler reads and applies — the race-free integration, since the
  handler owns the connection lifecycle and the enforcer must not close a socket
  out from under it. `Register`/`Block`/`Redirect`/`Disposition`/`Deregister`; a
  verdict for an unregistered flow is an error; concurrency-safe for many in-flight
  flows.
- `internal/gateway.Proxy` — an `http.Handler` forward proxy. Per request: mint a
  flow_id, read the body BOUNDED (the body it both classifies and forwards),
  register the flow, build a `gateway.Request`, call `gateway.Process` (classify in
  the worker → decide → audit → route BLOCK/REDIRECT through the Table), then act on
  the live connection by disposition — forward upstream via an `http.RoundTripper`,
  or 403, or 302 to a coaching URL.
- Observe-only by DEFAULT (D1): the flow enforcer is registered only when
  enforcement is enabled; off, a BLOCK decision leaves the disposition at allow, so
  the flow is forwarded and merely audited. Fail-OPEN on a classify/pipeline error
  (D17/D18): `Process` already audits the failure, so the proxy forwards with a
  high-severity log rather than turning a classifier failure into a DoS on egress.
- `cmd/openshield-gateway` — a thin binary: validate config fail-fast, start one
  `privileged.Worker`, open the Postgres ledger, build Gateway + Table + Proxy, and
  serve `http.Server{Handler: proxy}`.

## Capabilities

### Modified Capabilities
- `network-gateway`: gains the live proxy connector — it accepts a real HTTP
  connection, runs the pipeline, and applies the verdict to that connection
  (forward / block / redirect), observe-only by default, fail-open on error.
- `enforcement`: the socket-backed flow table carries a verdict as a per-flow
  disposition the owning connection handler applies, rather than the enforcer
  touching the socket directly.

## Impact

- New `internal/gateway.Table`, `internal/gateway.Proxy`, `cmd/openshield-gateway`;
  `docs/decisions.md` D73. Reuses the D70 Gateway, the D72 worker path, and the
  existing flow enforcer + FlowTable interface unchanged.
- Proven with REAL sockets and no Postgres (fake ledger): httptest upstream + Proxy
  on a real listening socket + a real proxy client — forward/block/redirect/
  observe-only/fail-open all asserted.
- NOT in scope (stated plainly): TLS interception + do-not-intercept list (N1.3);
  the worker POOL (one mutex-serialized worker is correct, a throughput follow-up);
  active teardown of long-lived/streaming flows. Respects D1/D49, D14, D17/D18, D72.
