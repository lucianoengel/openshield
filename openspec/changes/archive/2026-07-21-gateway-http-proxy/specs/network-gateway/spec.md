# network-gateway delta

## ADDED Requirements

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
