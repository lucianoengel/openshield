# network-gateway delta

## ADDED Requirements

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
