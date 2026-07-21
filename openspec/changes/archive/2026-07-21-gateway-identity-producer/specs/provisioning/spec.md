# provisioning delta

## ADDED Requirements

### Requirement: Client-role certificates are issued distinctly from agent and operator
Provisioning MUST issue a client-role certificate through a path distinct from the agent/operator
issuance, carrying a client-role marker and an authorization group, so a client certificate can never
be mistaken for an agent or operator certificate at the role gate. The agent/operator issuance MUST be
unchanged.

#### Scenario: A client certificate carries the client role and a group
- **WHEN** a client certificate is issued for an identity and a group
- **THEN** it is signed by the CA, marked with the client role, and carries the group, and it is not an
  agent or operator certificate
