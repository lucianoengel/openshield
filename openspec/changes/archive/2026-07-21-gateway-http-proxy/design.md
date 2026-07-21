## Context

`gateway.Gateway` (D70) assembles classify (in the worker, D72) → policy → decide →
audit and, if a flow enforcer is registered, routes BLOCK/REDIRECT to it via
`EnforceTarget(ctx, dec, flow_id)`. `enforcers/flow.Enforcer` resolves the flow_id
through a `FlowTable` (`Block`/`Redirect`). D70 proved this with a fake table and no
sockets. This change supplies the real table and the connector that owns the
sockets. The endpoint precedent is `cmd/openshield-engine` (D62): a thin connector
feeding the assembled pipeline; the logic lives in `internal/`, the binary is
wiring.

## Goals / Non-Goals

**Goals:**
- Accept a real HTTP connection, run it through the gateway, and apply the verdict
  to that connection.
- A socket-backed flow table that carries the verdict without racing the handler
  that owns the connection.
- Prove forward / block / redirect / observe-only / fail-open on real sockets.

**Non-Goals:**
- TLS interception + do-not-intercept list (N1.3).
- A worker POOL (one mutex-serialized worker is correct; throughput follow-up).
- Active teardown of long-lived/streaming flows (request/response only here).

## Decisions

**The flow table sets a DISPOSITION; the connection handler applies it.** The
naïve reading of "flow enforcer acts on the flow" is the enforcer closing the
socket. That races the handler, which owns the connection: it is mid-read of the
body or mid-forward. So the Table records a per-flow disposition (allow | block |
redirect) and the OWNING handler reads it after `Process` returns and carries it
out — forward, 403, or 302. `Block`/`Redirect` for a live flow means "set this
flow's disposition"; block-vs-reset (403 vs a TCP RST) is then a handler/config
choice, exactly as D69 said (an enforcement MODE, not a verdict). A verdict for an
unregistered flow_id is an error — a verdict for a flow that is not live is a bug,
surfaced not swallowed.

**Observe-only is registering-the-enforcer-or-not, and it composes with the
disposition default.** The Proxy registers `flow.New(table)` on the Gateway only
when enforcement is enabled. Off (the default, D1), `Process` never calls the
enforcer, the disposition stays `allow`, and the handler forwards — the flow is
observed and audited but not blocked. This is the same observe-first stance as the
engine (no enforcer = observe), now expressed through the live proxy: a deployer
opts INTO blocking egress.

**Fail-OPEN on a pipeline error, loudly, mirroring the watchdog (D17/D18).** If
`Process` returns an error (worker failure, stage timeout), the dispatcher has
ALREADY recorded the failure outcome via `OnOutcome`, so the failure is audited.
The proxy then FORWARDS the flow with a high-severity log rather than blocking it:
a classifier failure must not become a denial of service on all egress, exactly as
the endpoint watchdog auto-allows a blocked process on timeout and audits it.
Fail-closed (block on error) is a legitimate stricter posture, noted as a config
follow-up, not the default.

**The body is buffered bounded, because it is both classified and forwarded.** The
proxy reads the request body up to `maxBody` into memory: it needs the bytes to
hand to the worker (D72) AND to forward upstream. A body over the ceiling is
truncated for classification (the worker's own limit also applies) — the honest
skeleton buffers; streaming classification of very large bodies is a later concern,
noted. The buffered body is what both the classifier and the upstream request see.

**The binary is thin and does not link the parser.** `cmd/openshield-gateway`
validates config fail-fast, starts one `privileged.Worker`, opens the Postgres
ledger, and serves the Proxy. Like the engine binary it spawns the worker rather
than parsing itself, so its dependency graph excludes `internal/classify` — the
`go list -deps` guard is extended to cover the binary (D72).

## Risks / Trade-offs

- **Buffering the whole body caps request size in memory.** Bounded by `maxBody`;
  a streaming design is deferred. Stated.
- **Fail-open leaks on classifier failure.** A conscious choice for observe-first
  availability; audited every time; fail-closed offered as config later. Not hidden.
- **A forward proxy sees only what routes through it** — off-proxy egress is
  invisible, the same boundary the gateway architecture already states (endpoint
  covers local data; gateway covers egress that transits it). Restated, not new.
- **Plain HTTP only.** HTTPS bodies are opaque until TLS interception (N1.3); this
  connector classifies only cleartext HTTP. The proxy does not pretend otherwise.
