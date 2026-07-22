# network-gateway delta

## ADDED Requirements

### Requirement: The access proxy sanitizes inbound identity headers and injects the verified subject
The access proxy MUST strip client-supplied identity and forwarding headers from a request
before proxying it to a backend — so a client cannot feed a backend a spoofed identity or
pre-set the gateway's trusted subject header — and MUST inject a gateway-authoritative header
carrying the verified pseudonymous subject, so the backend consumes the real identity.

#### Scenario: A spoofed identity header never reaches the backend
- **WHEN** a client sends a request with a forged identity header and a pre-set subject header
- **THEN** the backend receives neither, and receives the gateway-injected subject equal to the verified certificate pseudonym
