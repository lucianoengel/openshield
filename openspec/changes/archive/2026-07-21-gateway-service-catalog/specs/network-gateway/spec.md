# network-gateway delta

## ADDED Requirements

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
