# network-gateway Specification

## Purpose
The network-domain pipeline assembly and its data plane — the network analogue of the endpoint engine plus its connector. Given a network request whose plaintext body the gateway holds, it classifies the body in the sandboxed worker (the network process does not link the parser), projects the result to a content-free classification, runs the network Event through the unchanged dispatcher and OPA policy, records the Decision to the forward-secure ledger, and — observe-only by default — dispatches the verdict to a flow enforcer keyed by flow_id. A plain-HTTP forward-proxy connector accepts a live connection and applies the verdict to it (forward / block / redirect) via a socket-backed flow table. TLS interception + do-not-intercept list and a worker pool are later increments.

## Requirements

### Requirement: The gateway classifies a request body in the sandboxed worker and never lets content leave it
The gateway MUST classify the plaintext body of a network request by sending it to the sandboxed
worker to parse — the gateway process MUST NOT link or run the parser itself — and MUST project the
worker's result to a content-free classification carrying only detector type, confidence, and
occurrence count (D10/D29). The body bytes MUST NOT appear in the Event, the Decision, the audit row,
or anything that crosses the process boundary, and a worker error MUST surface as a failure, never a
clean empty result (D17). This keeps the RCE-prone parser out of the network-capable process (D71
closed), while the gateway holds the bytes only long enough to proxy and to hand them to the worker.

#### Scenario: A request body carrying a CPF is classified in the worker without content crossing the boundary
- **WHEN** a network Request whose body contains a valid CPF is processed by the gateway backed by the
  real sandboxed worker
- **THEN** the resulting Decision is an audited ALERT and the classification records the detector type
  and count with no matched text
- **AND** the gateway package does not link the in-process classifier

#### Scenario: A worker error is an auditable failure, not a clean result
- **WHEN** the worker returns an error for a request body
- **THEN** the gateway terminates the request as a failure rather than treating it as no findings

### Requirement: A network request flows the existing pipeline to an audited Decision
The gateway MUST run the network Event and its boundary-safe classification through the EXISTING
`core.Dispatcher` (a body-classify stage plus the OPA policy stage) with the EXISTING audit sink as the
outcome hook, producing a Decision that is recorded to the forward-secure ledger. It MUST NOT modify
the dispatcher, pipeline State, Stage/Registry, the outcome sink, or the ledger.

#### Scenario: A CPF-bearing request produces an audited ALERT
- **WHEN** the gateway processes a request whose body triggers a detector under a policy that alerts
- **THEN** a Decision is produced and recorded to the ledger through the existing outcome sink

### Requirement: The gateway is observe-only by default
The gateway MUST record a Decision and enforce nothing when no flow enforcer is registered. Enforcement
MUST be enabled only by registering a flow enforcer, and only for the actions that enforcer advertises
(D1: observe-first, contain not prevent).

#### Scenario: With no enforcer registered, a BLOCK decision is recorded but not enforced
- **WHEN** the gateway processes a request whose policy decides BLOCK and no flow enforcer is registered
- **THEN** the Decision is classified and audited, and no enforcement action is taken

### Requirement: A registered flow enforcer receives the verdict keyed by flow_id
When a flow enforcer is registered and the Decision's action is one it advertises, the gateway MUST
dispatch the verdict to it, passing the request's `flow_id` as the enforce target, and MUST audit the
enforcement outcome — a failure high-severity, never silent (D14).

#### Scenario: A BLOCK decision routes to the flow enforcer with the flow_id
- **WHEN** the gateway processes a request whose policy decides BLOCK and a flow enforcer advertising
  BLOCK is registered
- **THEN** the flow enforcer's `EnforceTarget` is invoked with the request's `flow_id` as the target
- **AND** the enforcement outcome is audited

### Requirement: The gateway proxies a live HTTP connection and applies the verdict to it
The gateway MUST provide a forward-proxy handler that, for each request, reads the body bounded, runs
it through the gateway pipeline (classify in the worker, decide, audit), and applies the resulting
disposition to the LIVE connection: allow forwards the request upstream and copies the response back,
block responds 403 without forwarding, and redirect responds 302 to a coaching URL without forwarding.
The verdict MUST be carried to the connection through the flow table's disposition, not by the enforcer
closing the socket, so it never races the handler that owns the connection.

#### Scenario: A clean body is forwarded to the upstream
- **WHEN** a request whose body triggers no blocking verdict is proxied
- **THEN** the upstream receives the request and its response is returned to the client

#### Scenario: A blocked body is not forwarded
- **WHEN** a request whose policy decides BLOCK is proxied with enforcement enabled
- **THEN** the client receives 403 and the upstream never receives the request

#### Scenario: A redirected flow is sent to the coaching URL
- **WHEN** a request whose policy decides REDIRECT is proxied with enforcement enabled
- **THEN** the client receives 302 to the coaching URL and the upstream never receives the request

### Requirement: The proxy is observe-only by default and fails open on a pipeline error
The proxy MUST forward and merely audit when enforcement is not enabled, even for a decision that would
block (D1). On a classify or pipeline error the proxy MUST fail OPEN — forward the flow — because the
failure is already audited by the pipeline's outcome sink, and a classifier failure must not deny all
egress (D17/D18); the fail-open MUST be logged high-severity.

#### Scenario: Observe-only forwards a blocking decision
- **WHEN** a request whose policy decides BLOCK is proxied with enforcement NOT enabled
- **THEN** the upstream receives the request and the decision is recorded

#### Scenario: A worker error fails open and is audited
- **WHEN** the worker returns an error while classifying a proxied request body
- **THEN** the flow is forwarded and the failure is recorded

### Requirement: The proxy tunnels HTTPS via CONNECT without inspecting it
The proxy MUST handle the HTTP CONNECT method by establishing a blind TCP tunnel between the client and
the requested upstream — hijacking the client connection, dialing the upstream, acknowledging with 200,
and relaying bytes both directions until either side closes. Because the TLS session is end to end
between the client and the origin, the proxy MUST NOT attempt to classify tunneled bytes, and MUST log
each tunnel so the uninspected egress is operationally visible rather than silent. A failure to reach
the upstream MUST return 502.

#### Scenario: An HTTPS request transits the tunnel and is not classified
- **WHEN** an HTTPS client sends a request through the proxy via CONNECT and the upstream is reachable
- **THEN** the request succeeds end to end and its response is returned to the client
- **AND** nothing about the tunneled body is recorded to the audit ledger

#### Scenario: A tunnel to an unreachable upstream fails cleanly
- **WHEN** a CONNECT names an upstream that cannot be dialed
- **THEN** the proxy returns 502 rather than hanging or crashing

### Requirement: The proxy intercepts HTTPS to classify the inner request when authorised
When interception is enabled and the requested host is not on the do-not-intercept list, the proxy MUST
terminate the client's TLS by presenting a certificate it mints for the host (signed by a separate
interception CA), read the decrypted HTTP request, run it through the SAME pipeline as a plain-HTTP
request (classify in the worker, decide, audit, apply the disposition), and re-forward allowed requests
to the origin over a fresh TLS connection. The minted certificate MUST be one the client trusts (chain
to the interception CA), and an intercepted body MUST be classified — the tunnel's coverage gap closed.

#### Scenario: An intercepted HTTPS body carrying a CPF is classified and forwarded
- **WHEN** an HTTPS request whose body carries a CPF is intercepted with a client that trusts the
  interception CA and an origin the gateway trusts
- **THEN** the body is classified (recorded to the ledger) and the request is forwarded to the origin
- **AND** the response is returned to the client over the intercepted TLS

#### Scenario: A BLOCK verdict on an intercepted request is applied
- **WHEN** an intercepted HTTPS request's policy decides BLOCK with enforcement enabled
- **THEN** the client receives 403 and the origin never receives the request

### Requirement: The do-not-intercept list tunnels excluded hosts even when interception is on
The proxy MUST tunnel a host on the do-not-intercept list (exact host or domain suffix) blind, without
interception, even when interception is enabled — cert-pinned apps break under MITM and sensitive
egress must not be inspected. When no interception CA is configured the proxy MUST tunnel everything
(the D74 default).

#### Scenario: A do-not-intercept host is tunneled, not classified
- **WHEN** interception is enabled but the requested host is on the do-not-intercept list
- **THEN** the flow is tunneled blind and nothing about its body is recorded

### Requirement: The gateway classifies concurrent flows across a worker pool
The gateway MUST be able to classify concurrent flows in parallel by using a pool of workers rather
than serializing every body through a single worker. The pool MUST be a drop-in for the single worker
(the same classify interface), so the gateway pipeline is unchanged.

#### Scenario: The gateway uses a worker pool sized by configuration
- **WHEN** the gateway binary is configured with a worker-pool size
- **THEN** it starts that many workers and classifies flows across them, bounded by the pool size
