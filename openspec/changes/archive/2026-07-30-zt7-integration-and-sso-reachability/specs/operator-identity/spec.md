## ADDED Requirements

### Requirement: Operator authorization MUST be proven against the shipped binary

Verification SHALL exercise operator authorization end to end: the real control-plane binary, real mutual
TLS, and the role changed by the shipped command-line tool while a client keeps the same credential.

Handler-level tests prove the gate's logic and cannot prove the wiring — that the running binary reads what
the tool writes, and that a change reaches a connection already established. That gap is where operator SSO
shipped unusable.

#### Scenario: A demotion made with the CLI reaches a running server
- **WHEN** an operator's role is lowered with the command-line tool while they hold the same certificate
- **THEN** the routes above their new tier are refused without restarting either process

#### Scenario: A revocation made with the CLI reaches a running server
- **WHEN** an operator is revoked with the command-line tool
- **THEN** their existing credential opens nothing, and the listing shows the revocation as a fact

### Requirement: Enabling single sign-on MUST make a client certificate optional, not unverified

When operator SSO is enabled, the operator listener SHALL accept a connection with no client certificate,
and SHALL still verify any certificate that IS presented against the trusted authority.

Without the first, SSO is unreachable: an operator authenticating with a token has no certificate, so a
listener demanding one refuses them at the handshake before the token is read. Without the second, the
relaxation trades a working mutual-TLS gate for an open one — anyone could mint a certificate naming an
administrative role and the legacy fallback would honour it.

A deployment that has not enabled SSO SHALL keep demanding a client certificate.

#### Scenario: A token-authenticated operator can reach the listener
- **WHEN** SSO is enabled and a client presents a valid token and no certificate
- **THEN** the connection is established and the request is authorized from the operator record

#### Scenario: A certificate from an untrusted authority is still refused
- **WHEN** SSO is enabled and a client presents a certificate issued by an authority the server does not
  trust
- **THEN** the connection is refused

#### Scenario: Without SSO the listener is unchanged
- **WHEN** no identity provider is configured
- **THEN** a client certificate is required at the handshake as before
