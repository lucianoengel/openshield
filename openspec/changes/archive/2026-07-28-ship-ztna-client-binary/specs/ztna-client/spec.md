# ztna-client

## ADDED Requirements

### Requirement: The ZTNA client MUST be runnable as a shipped binary

The endpoint broker MUST be startable by an operator as a shipped binary configured by typed settings,
and MUST refuse to start when any of its required inputs is missing or invalid.

A capability that exists only as a library is not a capability of the product, however completely it
is implemented and tested.

#### Scenario: A configured client brokers to the access proxy

- **WHEN** an operator runs the client with a device certificate, a broker URL and a CA bundle
- **THEN** it MUST serve a local proxy that presents the device identity to the broker

#### Scenario: Missing device identity is fatal

- **WHEN** the client is started without a usable device certificate
- **THEN** it MUST exit rather than serve

#### Scenario: A non-loopback listen address is refused

- **WHEN** the client is configured to listen on an address that is not loopback
- **THEN** it MUST refuse to start

### Requirement: The client MUST state that it does not prevent bypass

On startup the client MUST report that it brokers access and does not prevent an application from
reaching the network by another route.

The name invites the stronger reading, and an operator who believes traffic is confined will not
discover otherwise until an application takes a direct route — at which point nothing reports it.

#### Scenario: Starting announces the limit

- **WHEN** the client starts
- **THEN** its output MUST state that it does not prevent bypass
