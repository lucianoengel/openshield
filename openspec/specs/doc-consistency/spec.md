

## Purpose

Automated guards on the project's own claims: the documented component set matches the binaries that
exist, claim surfaces carry no unqualified overclaim (a negation-aware check, not a naive grep), decision
numbers are unique, and the network gateway's scope is stated honestly. These exist because the
project's credibility rests on distinctions — tamper-evident not tamper-proof, detection not prevention —
that a careless edit can erase silently.

## Requirements

### Requirement: The documented component set matches the binaries that exist

The operator documentation SHALL name every command the project ships, and SHALL NOT name one that does
not exist. This SHALL be enforced by test in both directions. A runbook is read under pressure, and one
that omits a component or names a removed one costs an operator time exactly when they have none.

#### Scenario: An undocumented binary fails the check
- **WHEN** a command exists that the runbook does not name
- **THEN** the check fails, naming it

#### Scenario: A documented binary that no longer exists fails the check
- **WHEN** the runbook names a command that is not present
- **THEN** the check fails, naming it

### Requirement: Claim surfaces make no unqualified overclaim
A CI check MUST scan the claim surfaces (README and any user-facing copy) for unqualified
positive uses of overclaiming terms — tamper-proof, unhackable, fully/100% secure, prevents
exfiltration, guarantees safety — and MUST fail the build on one. It MUST NOT flag a use that is
negated, or explicitly escaped, or in a document that exists to discuss the terms.

The project's credibility rests on "tamper-evident, not tamper-proof" and "detection, not
prevention". A single careless README edit could erase that. But a naive grep is worse than
nothing here — proven on 2026-07-20, it false-positived on four honest negated uses, because this
project's discipline IS discussing the forbidden words. The check must tell a claim from its
denial.

#### Scenario: An honest negated claim surface passes
- **WHEN** the check scans a surface saying "it cannot prevent exfiltration" and "a tamper-proof
  log is impossible"
- **THEN** no violation is reported
- **AND** the real README passes, so the honest discipline is not punished

#### Scenario: An unqualified overclaim fails
- **WHEN** the check scans a surface asserting "OpenShield provides tamper-proof audit logs"
- **THEN** it reports a violation and fails the build
- **AND** a fixture asserts this, so the check is proven to catch the thing it exists for, not
  merely to pass on today's tree

#### Scenario: A deliberate use can be escaped
- **WHEN** a surface uses a forbidden term with an inline `<!-- allow: <term> -->` escape
- **THEN** it is not flagged
- **AND** research reports and the decision register are out of scope entirely

<!-- restored from 2026-07-21-add-doc-consistency-check -->

### Requirement: The decision register's numbers are unique
A CI check MUST verify that `docs/decisions.md` assigns each D-number at most once, failing the
build on a duplicate.

D-numbered referencing is the anti-drift discipline: living docs cite a decision by number rather
than restating it, which is what stopped the paraphrase drift that made brief.md stale twice. A
duplicated or collided D-number breaks that discipline at the source — the single point of truth.

#### Scenario: A duplicate D-number fails
- **WHEN** the register (or a fixture of it) assigns the same D-number twice
- **THEN** the check reports the duplicate and fails
- **AND** the real register passes, and a fixture with a collision fails

<!-- restored from 2026-07-21-add-doc-consistency-check -->

### Requirement: The network gateway's NIPS/ZT scope is stated honestly
The documentation MUST state that the network gateway is content-inspection egress DLP, not a network
intrusion-prevention system and not a Zero-Trust enforcement point, because it inspects only proxied
HTTP(S) and authenticates no subject (its subject is a hashed source address). The claim MUST be
phrased as what the system does NOT yet do, and MUST pass the overclaim check.

#### Scenario: The docs do not imply NIPS or ZT enforcement
- **WHEN** the documentation describes the network gateway
- **THEN** it states plainly that identity-aware authorization is roadmap, not built, and the overclaim
  check passes

<!-- restored from 2026-07-21-deploy-honesty-hardening -->
