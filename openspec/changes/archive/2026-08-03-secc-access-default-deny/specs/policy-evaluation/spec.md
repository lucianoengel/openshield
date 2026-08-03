## RENAMED Requirements

- FROM: `### Requirement: A policy that matches nothing is an explicit, recorded allow`
- TO: `### Requirement: A policy that matches nothing gets the stage's explicit, recorded default`

The old name asserted the outcome — "an allow" — which is exactly the part that turned out to be wrong.
The engine cannot name the outcome, because it is right for one kind of stage and wrong for the other.

## MODIFIED Requirements

### Requirement: A policy that matches nothing gets the stage's explicit, recorded default
If no policy rule produces a decision, the stage MUST emit an EXPLICIT decision carrying a reason that
says no rule matched — distinguishable in the ledger from a policy that affirmatively decided. This
MUST NOT be treated as a pipeline failure.

The outcome MUST be a property of the STAGE, not of the engine, because it is the stage that knows what
the decision is for:

- an OBSERVE-FIRST stage (the endpoint DLP pipeline) allows. An unmatched event there is the
  overwhelming majority of events — every ordinary file write on the host — and denying them would stop
  the machine rather than harden it.
- an ACCESS stage (the Zero-Trust gate) DENIES. An unmatched request there is a caller nobody
  authorized, and admitting it is the thing the gate exists to prevent.

Same engine, opposite correct answers. Before this, the engine allowed unconditionally and the access
proxy grants on ALLOW, so default-deny lived in the TEXT of the operator's Rego — a single
`decision := BLOCK if { not authorized }` line whose deletion, shadowing, or failure to keep up with a
new input shape silently converted a default-deny gate into a default-allow one, showing a reviewer only
a removed line they had to know was the whole security model.

Observe-only means the default is allow, but a silent allow and a reasoned "nothing matched" are
different records. The ledger must be able to tell "the policy considered this and let it pass" from
"no rule applied", and for an access stage it must further distinguish an authored denial from an
unmatched request — those are different operator problems, one a decision and the other a hole.

#### Scenario: No matching rule yields a reasoned allow in an observe-first stage
- **WHEN** a policy with no matching rule evaluates an Event
- **THEN** the Decision is ALLOW with a reason indicating no rule matched
- **AND** the outcome is a normal decision, not a failure

#### Scenario: No matching rule denies in an access stage
- **WHEN** an access policy has no rule matching the request
- **THEN** the Decision is a denial whose reason says no rule matched, so the gate refuses a caller its
  policy never mentioned

#### Scenario: An authored decision is never replaced by the default
- **WHEN** a rule DOES match
- **THEN** its own action and reason are what the Decision carries

## ADDED Requirements

### Requirement: An access policy is proven to deny an unknown principal before it is used

Loading a module as an ACCESS policy SHALL evaluate it against a canonical principal carrying no
identity, no role and no device posture, and SHALL FAIL when that principal is ALLOWED.

This covers what a no-match default cannot. A module that allows unconditionally, or whose predicate is
vacuously true when the fields it reads are absent — `role != "banned"` reads like a denylist and admits
every caller whose role could not be resolved — MATCHES, so no default fires. Such a policy is not
incomplete; it is wrong, and it admits everyone who can complete the handshake.

The check SHALL run at LOAD, not at first request: the failure mode of a Zero-Trust gate must be "does
not start", never "starts and admits everyone".

The canonical principal SHALL be assembled by the same code that assembles a real request's policy
input. A probe evaluating a shape the policy never actually sees passes for the wrong reason, and the
input shape has gained fields repeatedly.

#### Scenario: A policy admitting an unknown principal is refused
- **WHEN** a module offered as an access policy allows a request with no identity, role or posture
- **THEN** loading fails, naming the reason, and the component does not start

#### Scenario: A policy that merely says nothing still loads
- **WHEN** an access policy authorizes some callers and is silent about the rest
- **THEN** it loads, because it never admits an unknown principal — the no-match default answers for the
  callers it does not mention
