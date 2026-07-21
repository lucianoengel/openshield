# network-gateway delta

## ADDED Requirements

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
