## ADDED Requirements

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
