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

### Requirement: The gateway projects decisions to the control plane, boundary-safe and opt-in
When a telemetry transport is configured, the gateway MUST project each Decision — with a redacted
network Event — to the control plane through the signed transport, additively to the local ledger. It
MUST NOT project when no transport is configured (the default), MUST NOT fail the request on a
projection error (the local ledger is the system of record), and the projected network metadata MUST
omit the user IP and the URL path while retaining the destination and verdict.

#### Scenario: A decision projects a redacted network Event plus the Decision
- **WHEN** the gateway processes a network request with a telemetry transport configured
- **THEN** it publishes the Decision and a network Event whose src_ip and http_path are empty and whose
  destination (sni_host / dst) is retained

#### Scenario: No projection without a transport
- **WHEN** the gateway processes a request with no telemetry transport configured
- **THEN** nothing is projected

#### Scenario: A projection failure does not fail the request
- **WHEN** the telemetry transport returns an error while projecting
- **THEN** the request still completes and the decision remains recorded locally

### Requirement: Tunneled flows are recorded as a metadata-only audit entry
The gateway MUST record a metadata-only ledger entry for every flow it tunnels without inspection
(both the blind tunnel when interception is off and a do-not-intercept host when it is on), naming the
destination host and the reason it was not inspected, with NO body, NO URL path, and NO decision — so
uninspected egress is visible in the audit trail rather than silent. The recording MUST be best-effort:
an append failure is logged and the tunnel still proceeds. An inspected (intercepted) flow MUST NOT
record a tunnel entry — its Decision is recorded instead, so the two paths are distinct in the ledger.

#### Scenario: A blind-tunneled flow records a metadata-only tunnel entry
- **WHEN** an HTTPS flow is tunneled without inspection
- **THEN** the ledger records a "tunneled" entry naming the destination host and the reason, with no
  decision and no body

#### Scenario: A do-not-intercept host records a tunnel entry with that reason
- **WHEN** interception is on but the host is on the do-not-intercept list
- **THEN** the flow is tunneled and a "tunneled" entry records the host with reason do-not-intercept

#### Scenario: An intercepted flow records a decision, not a tunnel entry
- **WHEN** a flow is intercepted and inspected
- **THEN** its Decision is recorded and no "tunneled" entry is written

### Requirement: The interception CA is hot-rotatable, fail-safe
The cert minter MUST support replacing the interception CA at runtime: validate the new CA first,
then atomically swap it and flush the leaf cache so no leaf signed by the previous CA is served
afterward. A rotation with an invalid CA MUST fail without changing the active CA, so a bad rotation
never breaks interception or silently disables it. Rotation MUST be safe under concurrent minting.

#### Scenario: After rotation, leaves chain to the new CA and not the old
- **WHEN** a leaf is minted for a host under CA1, then the minter is rotated to CA2, then a leaf is
  minted for the same host
- **THEN** the new leaf chains to CA2 and no longer verifies against CA1

#### Scenario: A bad rotation keeps the working CA
- **WHEN** rotation is attempted with an invalid CA
- **THEN** it returns an error and the minter continues minting valid leaves under the previous CA

### Requirement: A verified client identity resolves into the Zero-Trust context
The gateway MUST resolve a verified client certificate into a pseudonymous identity and an
authorization role in the pipeline context, replacing the hashed source address as the subject. The raw
identity MUST be pseudonymised one-way at the boundary and never enter the pipeline. A certificate that
is not a client certificate MUST be rejected as an identity. Device posture MUST remain absent (a
separate producer), so a cert-authenticated but unattested device still fails closed under the identity
context policy.

#### Scenario: A client certificate yields a pseudonymous subject and role
- **WHEN** a valid client certificate is resolved
- **THEN** the context carries a pseudonymous subject (not the raw identity) and the certificate's group
  as the role, with device posture marked absent

#### Scenario: A non-client certificate is rejected
- **WHEN** an agent or operator certificate is presented as a client identity
- **THEN** it is rejected

### Requirement: The gateway brokers identity-authenticated access to an internal service and fails closed
The gateway MUST provide an access-proxy handler that authenticates the client by certificate, resolves
the verified identity into the pipeline context, makes a per-request authorization decision through the
pipeline on that identity, and reverse-proxies allowed requests to an internal service. A request with
no valid client identity MUST be refused. On any pipeline error the access decision MUST FAIL CLOSED
(deny) — the deliberate opposite of the egress proxy's fail-open — because a Zero-Trust gate must never
grant access on an error. The Event subject for an authenticated request MUST be the verified identity
pseudonym, not the source address.

#### Scenario: An authorized identity reaches the internal service
- **WHEN** a client presents a valid client certificate for a role the policy authorizes
- **THEN** the request reaches the internal service and its response is returned, and the recorded
  subject is the verified pseudonym

#### Scenario: An unauthorized identity is denied and the service is never reached
- **WHEN** a client's policy decision is not allow (wrong role), or the client presents no client
  certificate, or the pipeline errors
- **THEN** the request is refused and the internal service is never reached

### Requirement: The access proxy routes to catalogued internal services and authorizes per service
The access proxy MUST front a catalog of internal services and route each request to the service named
by its host, authorizing per service on the client's identity. A request for a service NOT in the
catalog MUST be refused (not forwarded to any host), so the gateway is an explicit allow-list of
services, never an open relay. The same identity MUST be able to reach one service and be denied
another (identity-based microsegmentation), and the pipeline Event MUST carry which service was targeted
so the policy can decide per service.

#### Scenario: The same identity reaches one service and is denied another
- **WHEN** an identity authorized for service A but not service B requests each
- **THEN** the request to A reaches A's upstream and the request to B is denied, with B's upstream never
  reached

#### Scenario: An unknown service is refused
- **WHEN** a request names a service not in the catalog
- **THEN** it is refused and no internal upstream is reached

### Requirement: The gateway performs continuous verification on published risk, deciding locally
The gateway MUST be able to read a published per-subject risk score and enrich the access decision
context with it, so a policy can step-up or deny a subject whose risk has risen mid-session. The
decision MUST be made by the local policy reading the risk as data — the server MUST NOT command the
gateway to cut access. Absent risk MUST NOT itself deny (it means analytics is quiet, not danger),
unlike absent device posture which fails closed; the presence of a risk score MUST be distinguishable
from its absence.

#### Scenario: Rising risk cuts access mid-session, decided locally
- **WHEN** an authorized identity accesses a service, then a high risk score is published for that
  subject, then it accesses again
- **THEN** the first access is allowed and the second is denied by the local policy, with the service
  not reached

#### Scenario: Absent risk does not deny an authorized identity
- **WHEN** an authorized identity accesses a service and no risk is published for it
- **THEN** access is allowed (absent risk is not high)

### Requirement: The gateway runs a client-cert access-proxy mode, fail-fast on misconfiguration
The gateway binary MUST support an access-proxy mode that serves the access handler over TLS requiring a
verified client certificate, with an identity-aware policy loaded from a file and a service catalog from
configuration. It MUST validate its access configuration at startup and ABORT on any missing required
input (client CA, server certificate, policy, or an empty catalog) — a Zero-Trust gate must never start
misconfigured and permissive. A gateway process runs as either the egress proxy or the access proxy.

#### Scenario: The access mode requires a client certificate and a complete configuration
- **WHEN** the gateway is started in access mode with a client CA, server certificate, policy, and a
  non-empty catalog
- **THEN** it serves the access proxy over client-certificate-required TLS; and if any required input is
  missing it aborts at startup rather than starting permissive

### Requirement: The gateway populates its risk store from published risk updates
The gateway MUST subscribe to published risk updates and record each into its risk store, so continuous
verification decides on real risk. Applying an update MUST record the subject's latest risk, and a
malformed update MUST be rejected, not silently ignored.

#### Scenario: A published risk update reaches the risk store
- **WHEN** the gateway applies a risk update for a subject
- **THEN** the risk store returns that subject's risk

### Requirement: The access proxy enriches decisions with published device posture, unattested devices fail closed
The gateway MUST subscribe to published device-posture updates and record each into a posture store, and
the access proxy MUST enrich each request's decision context with the connecting subject's posture. The
proxy MUST resolve posture under the SAME shared canonical device-pseudonym derivation the producer
publishes under and the roster verifies under — it MUST NOT derive the posture-lookup subject by any
independent or divergent scheme, so a device whose posture arrived through the real producer path is
actually recognized. A subject with published posture MUST carry it (marked present); a subject with NO
published posture MUST keep posture absent, so a policy requiring an attested device denies it (the
tamper-lockout). A malformed posture update MUST be rejected, not silently ignored.

#### Scenario: A compliant device is allowed and an unattested device is denied
- **WHEN** a policy requires an attested device, and a subject has posture published for it through the
  real producer path (keyed by the shared canonical pseudonym of its enrolled agent identity)
- **THEN** the connecting device certificate for that agent resolves posture as present and is allowed;
  and a device whose agent has no published posture is denied

### Requirement: A signed OIDC bearer token resolves into a verified Zero-Trust identity
The gateway MUST verify a signed OIDC/JWT bearer token — its issuer, audience, expiry, and
signature — against a configured key set, and resolve a valid token into the same
pseudonymous Zero-Trust identity as a client certificate (a one-way subject and an
authorization role from a configured claim). A token that is malformed, expired, not yet
valid, signed by an unknown or wrong-type key, carries a wrong issuer or audience, uses an
unsafe algorithm, or lacks a subject or role MUST be rejected — never resolved to a partial
or defaulted identity. The signing key set MAY be sourced from a live JWKS endpoint so an
identity-provider key rotation is picked up without a restart; when it is, the gateway MUST refresh
the keys in the BACKGROUND (the token-verification path MUST NOT perform a network fetch), MUST serve
the last-good keys when a refresh fails (a provider outage MUST NOT black out verification of tokens
signed by still-valid keys), and MUST rate-limit any refresh triggered by an unknown key id (an
unknown-key-id flood MUST NOT drive unbounded fetches). An unknown key id MUST remain a rejection until
a refresh makes the key known.

#### Scenario: A valid token resolves and an adversarial token is rejected
- **WHEN** a valid OIDC token is presented
- **THEN** it resolves to a pseudonymous subject and role; and a tampered, expired, or unsafe-algorithm token is rejected

#### Scenario: A rotated key is picked up, and a provider outage serves stale
- **WHEN** the signing key set is sourced from a JWKS endpoint, the provider rotates to a new key id, and later the JWKS endpoint fails
- **THEN** a token signed by the new key verifies once a background refresh has picked it up (without a restart and without the verification path fetching), and while the endpoint is failing a token signed by a still-known key continues to verify against the last-good keys

### Requirement: The gateway applies only signed, verified risk and posture updates
The gateway MUST verify the Ed25519 signature of every published risk and device-posture
update against a trusted publisher key BEFORE applying it — risk against the control-plane
key, posture against the posture-publisher key — and MUST reject and count any update that is
unsigned, tampered, wrong-key, or malformed, never applying it. A channel with no configured
trusted key MUST NOT be subscribed, so an unsigned update is never applied. Verification MUST
occur before the inner update is parsed.

#### Scenario: A forged risk or posture update cannot change the store
- **WHEN** the gateway receives risk and posture updates
- **THEN** a validly-signed update is applied, and an unsigned, wrong-key, or tampered update is rejected and counted while the legitimate value stands

### Requirement: The access proxy sanitizes inbound identity headers and injects the verified subject
The access proxy MUST strip client-supplied identity and forwarding headers from a request
before proxying it to a backend — so a client cannot feed a backend a spoofed identity or
pre-set the gateway's trusted subject header — and MUST inject a gateway-authoritative header
carrying the verified pseudonymous subject, so the backend consumes the real identity.

#### Scenario: A spoofed identity header never reaches the backend
- **WHEN** a client sends a request with a forged identity header and a pre-set subject header
- **THEN** the backend receives neither, and receives the gateway-injected subject equal to the verified certificate pseudonym

### Requirement: The access proxy can resolve identity from a verified OIDC token
The access proxy MUST support resolving the request's user identity from a verified OIDC/JWT bearer
token when an OIDC verifier is configured, using the token's subject and role for authorization and
layering it on the required mutual-TLS device certificate. A request without a token MUST be refused,
a token that fails verification MUST be refused, and the proxy MUST fail closed on any identity
error. Without a configured verifier, the client certificate MUST remain the identity.

#### Scenario: A valid token authorizes and an invalid one is refused
- **WHEN** the access proxy has an OIDC verifier configured and receives a request with a valid token, no token, and an invalid token
- **THEN** the valid token's identity is authorized through the policy and reaches the service, the missing token is refused with 401, and the invalid token is refused with 403 without reaching the service

### Requirement: The access proxy composes user and device credentials
When resolving access, the proxy MUST treat the user identity (from an OIDC token when configured, or
the client certificate otherwise) and the device separately: the device is the enrolled client
certificate, and device posture MUST be looked up by the device certificate's identity, not the
user's. An unenrolled device certificate MUST be refused. A policy requiring both a user attribute and
a compliant device MUST authorize only when both hold, so a valid user on an unattested device is
denied and posture published for a user's subject does not satisfy a device requirement.

#### Scenario: A valid user on an unattested device is denied
- **WHEN** a policy requires a role and a compliant device, and a valid-token user connects from a device with no published posture, then from a device with compliant posture published for the device
- **THEN** the request is denied while the device is unattested (even with the valid user token) and authorized once the device's own posture is compliant, and posture published for the user's subject does not satisfy the device requirement


### Requirement: The forward proxy inspects the response body

When response inspection is enabled, the system SHALL buffer the response body up to a memory bound,
decode gzip content for classification, classify it through the pipeline as an inbound event, and audit
the decision — while always delivering the exact upstream bytes to the client. A response larger than the
bound MUST be forwarded uninspected (an audited coverage gap, not a refusal), and a read or classification
error MUST forward the response rather than break it (fail open). With inspection disabled, the response
MUST be streamed through unchanged.

#### Scenario: A sensitive response is classified, audited, and delivered

- **WHEN** response inspection is on and an upstream returns a body containing sensitive content
- **THEN** the response is classified and the decision audited, and the client still receives the exact
  upstream response

#### Scenario: An over-cap response is forwarded uninspected

- **WHEN** a response body exceeds the memory bound
- **THEN** it is delivered intact to the client and the uninspected coverage is recorded, not refused

#### Scenario: Inspection disabled leaves the response unchanged

- **WHEN** response inspection is off
- **THEN** the response is streamed through exactly as before

### Requirement: A transparent inline mode intercepts and decides a redirected flow at L4

The system SHALL provide an opt-in transparent inline mode that accepts a TCP flow redirected to it
(TPROXY), recovers the flow's ORIGINAL destination from the accepted connection, and decides the flow
through the pipeline on its metadata (source and original destination). A flow the pipeline blocks SHALL
be dropped — the client connection is closed and no bytes reach the destination. A flow the pipeline
allows SHALL be spliced bidirectionally to its original destination, so an allowed flow is transparent
to both endpoints. The transparent mode SHALL be off by default (an inline data-plane is an explicit
deploy choice).

#### Scenario: A flow to a blocked destination is dropped
- **WHEN** a redirected flow's original destination is one the pipeline blocks
- **THEN** the connection is dropped and no data is forwarded to the destination

#### Scenario: A flow to an allowed destination is spliced through
- **WHEN** a redirected flow's original destination is one the pipeline allows
- **THEN** the flow is connected to that destination and data passes in both directions

### Requirement: The inline data-plane preserves egress fail-open

The transparent inline mode MUST fail open: a pipeline error while deciding a flow MUST forward the flow
to its original destination rather than drop it, so a detection failure degrades to a passive wire and
never becomes a network outage. If the transparent listener cannot be created (for example, without the
required network-admin capability), the system MUST fail to WIRE — log the condition and continue
running the rest of the gateway — and MUST NOT take the network down because inline could not arm.

#### Scenario: A pipeline error forwards the flow
- **WHEN** deciding a redirected flow returns an error
- **THEN** the flow is forwarded to its original destination (fail-open), not dropped

#### Scenario: An un-armable inline plane does not break the gateway
- **WHEN** the transparent listener cannot be created
- **THEN** the condition is logged and the gateway continues without the inline plane, forwarding nothing to a blackhole

### Requirement: The transparent inline mode decides a flow on its TLS SNI

The transparent inline mode SHALL peek the initial bytes of a redirected flow without consuming them,
extract the server name (SNI) from a TLS ClientHello, and decide the flow on that hostname in addition to
its destination IP, so a flow to a policy-blocked domain served from a shared IP is dropped. The SNI
parser MUST be defensive: a buffer that is not a ClientHello, is truncated, has no SNI, or carries an
attacker-crafted length MUST yield no hostname rather than an error or a crash. When the flow is allowed
and spliced, the peeked bytes MUST be replayed to the destination so the flow is byte-for-byte
transparent (the destination sees the original handshake). A flow with no recoverable SNI (non-TLS, a
peek timeout, or a parse miss) MUST fall back to the destination-IP decision and MUST NOT be dropped on
the peek failure (fail-open).

#### Scenario: A flow to a blocked domain on a shared IP is dropped by SNI
- **WHEN** a redirected TLS flow's ClientHello carries an SNI the policy blocks, even though its destination IP is not itself blocked
- **THEN** the flow is dropped

#### Scenario: An allowed flow's handshake is replayed intact
- **WHEN** a redirected flow is allowed after peeking its ClientHello
- **THEN** the peeked bytes are delivered to the destination first and the flow proceeds byte-for-byte transparently

#### Scenario: A non-TLS or SNI-less flow falls back and is not dropped
- **WHEN** a redirected flow carries no recoverable SNI (not TLS, truncated, or no server_name)
- **THEN** the flow is decided on its destination IP and is not dropped because the peek found no SNI
