# network-gateway (delta)

## ADDED Requirements

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
