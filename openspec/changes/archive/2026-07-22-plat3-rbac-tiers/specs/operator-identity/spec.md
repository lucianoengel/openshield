## MODIFIED Requirements

### Requirement: A verified certificate is authorized per route by its role
A mutual-TLS route MUST authorize a verified client certificate by the ROLE carried in its Subject
Organizational Unit, not merely authenticate it. Beyond the `agent` role (for enrollment), the
operator surface MUST support TIERED roles — `analyst`, `responder`, and `admin` — ordered so a higher
tier satisfies a lower requirement (`analyst` < `responder` < `admin`); the legacy `operator` role
MUST rank as `admin` so existing operator certificates keep full access. A route MUST gate on a
MINIMUM tier: the read surface (alerts, search, events, overdue, incidents, subject) requires at least
`analyst`, the mutating acknowledgements require at least `responder`, and the full investigation view
requires `admin`. A certificate whose role ranks below a route's minimum MUST be refused `403`, and an
`agent` (or unknown/absent) role MUST NOT be authorized for any operator route.

The role is read from the VERIFIED peer certificate (CA-verified by the handshake), never from the
request. This is authorization by a certificate attribute the issuing CA sets — as trustworthy as the
CA's issuance discipline (the same trust class as any PKI), and the win is that the role is CHECKED.

#### Scenario: The view endpoint requires the admin tier
- **WHEN** a client with a verified `agent`-role certificate (or any cert whose role ranks below admin, e.g. a bare `analyst`) calls the view endpoint
- **THEN** the request is refused `403 Forbidden` and no investigation is returned or recorded
- **AND** a client with a verified `admin`-role (or legacy `operator`) certificate is served

#### Scenario: Tiers are ordered — a higher tier satisfies a lower requirement
- **WHEN** an `analyst` cert reads the alert queue, a `responder` cert acknowledges an alert, and an `analyst` cert attempts to acknowledge
- **THEN** the analyst read is served, the responder acknowledgement is served, and the analyst acknowledgement is refused `403` (analyst ranks below responder), while an `admin`/legacy-`operator` cert is served on all of them

#### Scenario: The enrollment endpoint requires the agent role
- **WHEN** a client with a verified operator-tier certificate calls the enrollment endpoint
- **THEN** the request is refused `403 Forbidden` and no enrollment occurs
- **AND** a client with a verified `agent`-role certificate can enroll
