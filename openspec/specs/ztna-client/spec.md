# ztna-client Specification

## Purpose
The ENDPOINT half of Zero-Trust access (ZT-4): a local broker that applications reach unmodified, which
presents the DEVICE's enrolled certificate to the access proxy so a connection is authorized by device
identity and user identity together. It refuses to start without an identity, binds loopback only, and
never falls back to an unauthenticated or direct connection when the broker refuses.

It brokers access; it does not by itself prevent an application from bypassing it — enforcing the path with
routing and firewall rules is separate work.

### Requirement: The endpoint brokers access with the device's own identity

The client SHALL accept application traffic locally and forward it to the access broker over a
mutually-authenticated connection presenting the DEVICE's certificate, attaching the user's credential
where one is configured. The internal service SHALL be reached only through that brokered path.

#### Scenario: An attested, authorized device reaches an internal service
- **WHEN** an application sends a request through the local broker on a device whose certificate is
  enrolled, attested and authorized by policy
- **THEN** the request reaches the internal service and the response is returned to the application

#### Scenario: The request carries the device identity, not the application's
- **WHEN** the client forwards a request
- **THEN** the connection to the broker presents the device certificate

### Requirement: An unauthorized or unattested device is refused, and told why

When the broker refuses, the client SHALL surface the refusal to the application as an error that names the
broker's reason. It SHALL NOT retry the request unauthenticated, and it SHALL NOT fall back to a direct
connection to the internal service.

#### Scenario: An unattested device is refused
- **WHEN** the device is not attested and policy requires attestation
- **THEN** the request fails with the broker's refusal surfaced, and no direct connection is attempted
- **AND** the test FAILS if the client falls back to connecting directly

### Requirement: The client refuses to run without a device identity

The client SHALL refuse to start when it has no device certificate, rather than starting and forwarding
traffic unauthenticated — a broker that silently forwards without the identity it exists to present is
worse than no broker, because it looks like protection.

#### Scenario: No identity means no listener
- **WHEN** the client is started without a device certificate
- **THEN** it exits with an error and opens no local listener

### Requirement: SSO identity is verified on the request path
When an OIDC issuer is configured, the access proxy MUST resolve the USER identity from a verified bearer
token, and a request without a valid token MUST be refused even with a valid device certificate.

The mTLS certificate says which DEVICE; the token says which PERSON. A gateway that verified device
identity perfectly and ignored the token would admit anyone holding a laptop. Eleven settings configured
this path and none was exercised against a running binary before D316.

#### Scenario: A valid token authorizes and its role reaches the policy
- **WHEN** a request presents a device certificate and a token signed by an enrolled key, carrying the
  authorized role
- **THEN** it is admitted and reaches the origin
- **AND** a token verified from the SAME key but carrying an unauthorized role is refused, because
  verifying who someone is, is not deciding what they may reach

#### Scenario: A forged, expired, misaddressed or foreign token is refused
- **WHEN** a token is signed by an unknown key, expired well beyond the leeway, minted for another
  audience, or issued by another issuer
- **THEN** each is refused and the origin is never reached
- **AND** these are asserted ALONGSIDE the positive case, because negatives all pass when everything is
  refused: the first version of these signed with an algorithm the verifier rejects outright, so six of
  seven scenarios were green and vacuous

#### Scenario: A broken identity source aborts startup
- **WHEN** the OIDC key directory is unreadable, or the JWKS URL is plaintext HTTP
- **THEN** the gateway refuses to start
- **AND** a zero-trust gate that comes up with a broken identity source admits requests it cannot
  attribute, and looks healthy doing it; a plaintext key source lets anyone on the path mint identities
