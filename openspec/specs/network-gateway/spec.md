# network-gateway Specification

## Purpose
The network-domain pipeline assembly — the network analogue of the endpoint engine. Given a network request whose plaintext body the gateway holds, it classifies the body in-process (reusing the pattern classifier), projects the result to a content-free classification, runs the network Event through the unchanged dispatcher and OPA policy, records the Decision to the forward-secure ledger, and — observe-only by default — dispatches the verdict to a flow enforcer keyed by flow_id. Proven end to end without sockets; real sockets, a socket-backed flow table, and TLS interception are later increments.

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
