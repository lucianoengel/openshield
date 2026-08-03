## ADDED Requirements

### Requirement: The access gate's default-deny does not depend on the operator's policy text

The gateway SHALL load its access policy as an ACCESS stage, so a request no rule matches is DENIED by
the engine, and SHALL refuse to start when the module admits a principal it knows nothing about.

Until this, the gateway loaded an ordinary policy stage, whose no-match outcome is ALLOW — and the
access proxy grants on ALLOW. "Identity-aware and default-deny" was therefore a claim about a line of
operator-authored Rego rather than a property of the gate, and every access policy in the tree ends with
that line. A gate whose security model can be removed by deleting one rule from a configuration file is
not default-deny; it is default-allow with a convention.

#### Scenario: An incomplete policy still denies
- **WHEN** a gateway is started with an access policy that authorizes some callers and says nothing
  about the rest, and an authenticated caller no rule mentions requests a catalogued service
- **THEN** the request is refused and never reaches the internal service
- **AND** an authorized caller is still served, because the default applies to unmatched requests and
  not to every request

#### Scenario: A permissive policy stops the gateway starting
- **WHEN** a gateway is started with an access policy that allows a principal with no identity, role or
  posture
- **THEN** the gateway reports the refusal, never begins serving, and leaves nothing listening on the
  access port
