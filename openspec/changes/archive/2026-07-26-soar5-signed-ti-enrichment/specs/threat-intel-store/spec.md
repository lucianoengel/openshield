## ADDED Requirements

### Requirement: A feed's signature is verified before it is parsed

An IOC feed MAY carry a detached ed25519 signature over its exact bytes. When a verification key is
configured, ingest SHALL verify the signature **before** the feed is parsed, and SHALL refuse the feed
**as a whole** if verification fails. No indicator from an unverified feed may be stored, and no part of
an unverified feed may be applied — a partially applied feed is an attacker's best outcome, because it
lets them drop the indicators that would catch them and keep the rest.

#### Scenario: A tampered feed is refused entirely
- **WHEN** a feed's bytes do not match its signature
- **THEN** ingest fails, the store is unchanged, and the feed's content is never parsed

#### Scenario: A validly signed feed is ingested
- **WHEN** a feed's signature verifies against the configured public key
- **THEN** its indicators are stored with the feed's name recorded as their provenance

#### Scenario: A signature for a different feed does not transfer
- **WHEN** a valid signature for one feed is presented with a different feed's bytes
- **THEN** verification fails and nothing is stored

### Requirement: A feed is a snapshot, so ingest replaces rather than appends

Ingesting a feed SHALL replace that feed's indicator set atomically. An indicator withdrawn from the feed
SHALL disappear from the store on the next ingest. Appending would make a taken-down indicator flagged
forever and a withdrawn false positive impossible to withdraw. Indicators from other feeds MUST be
unaffected.

#### Scenario: A withdrawn indicator disappears
- **WHEN** a feed is re-ingested without an indicator it previously contained
- **THEN** that indicator is no longer in the store

#### Scenario: One feed's ingest does not disturb another's
- **WHEN** two feeds are ingested and one is re-ingested
- **THEN** the other feed's indicators are unchanged

#### Scenario: Provenance is recorded
- **WHEN** a feed is ingested
- **THEN** the feed's name, content digest, indicator count and ingest time are recorded, so an analyst
  can tell which feed and which version asserted an indicator

### Requirement: The store and the inline engine share one matcher

Indicator matching SHALL have exactly one implementation. The store SHALL materialize the same feed
structure the inline network engine uses, and any consumer matching an observable SHALL call that
matcher. Re-implementing matching for the analytical path would let the parent-suffix domain semantics,
the CIDR containment, or the minimum-length URI-indicator guard drift between the path that blocks and
the path that reports.

#### Scenario: A subdomain of a feed domain matches
- **WHEN** an observable is a subdomain of an indicator domain
- **THEN** it matches, and a domain that merely ends with the indicator's characters (a different label)
  does not

#### Scenario: A store-materialized feed matches identically to a parsed one
- **WHEN** the same indicators are loaded from a parsed feed and from the store
- **THEN** both match the same observables

### Requirement: An operator ingests a feed locally, never over the network

Feed ingest SHALL be an operator-local operation, not an HTTP route. A network endpoint that accepts
indicator sets would let anything that reaches it decide what the platform calls a threat, defeating the
signature requirement it exists alongside.

#### Scenario: Ingest is a subcommand
- **WHEN** an operator ingests a feed
- **THEN** it is performed by a local command against the database, and no route accepts feed content
