# network-gateway delta

## ADDED Requirements

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
