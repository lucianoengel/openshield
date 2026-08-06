## ADDED Requirements

### Requirement: A recorded view MUST be attributed from the authenticated principal, never re-derived

The identity written into a view record SHALL be the authenticated principal already resolved by the
operator gate for that request.

Attribution that re-derives an identity from the connection answers "" for an operator who authenticated
with a bearer token, so the recording would fail — or worse, be skipped — for exactly the sign-on path a
console uses. Authenticating twice by two different rules is how those two answers came to disagree
before, and a recording layer must not reintroduce it.

A request that reaches the recording layer with no principal SHALL be refused as an internal fault rather
than treated as an anonymous read: past the operator gate it is impossible, so it means the layer was
mounted outside the gate, which is a wiring error and not an authorization outcome.

#### Scenario: A bearer-authenticated operator's read is attributed
- **WHEN** an operator who authenticated without a client certificate reads an audited surface
- **THEN** the recorded view carries their principal

#### Scenario: A read reaching the recording layer with no principal is refused
- **WHEN** the recording layer is reached without an authenticated principal
- **THEN** the request is refused as an internal fault and nothing is recorded

### Requirement: An operator MUST have an access path to what is held about them, and it MUST end in erasure

What the platform holds about an operator's own reading SHALL be readable through the privacy officer's
view-audit route, and SHALL be erased by the retention window rather than kept indefinitely.

The view audit stores raw operator identities — attributable by design, because a pseudonymised
accountability record accounts to nobody. That makes the operator a data subject of this table, and a
store of personal data with no access path and no erasure is the gap this change closes. The access path
is the officer's existing route rather than a second endpoint: a self-service one would be a new authority
to design, and an operator who could read their own record could confirm exactly when their reading
started being examined.

#### Scenario: What is held about one operator can be read
- **WHEN** the privacy officer asks for the recorded views of a named operator principal
- **THEN** every view recorded against that principal is returned

#### Scenario: The record does not outlive its window
- **WHEN** a view record passes the configured retention window
- **THEN** it is deleted, so the store of operator identities is bounded rather than permanent
