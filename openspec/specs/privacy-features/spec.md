# privacy-features Specification

## Purpose
Privacy-law features as Phase-1 architecture (D20): retention purge that tombstones (erases content, keeps the chain verifiable), retention classes with an investigation hold, exclusion at the source, a tamper-evident view-record mechanism, and pinned pseudonymisation/purpose invariants.
## Requirements
### Requirement: Retention purge erases content without breaking the chain
Retention purge MUST erase an expired entry's personal data while preserving the hash chain's
verifiability. A purged (tombstoned) entry MUST keep its sequence, previous-hash, hash and
signature; verification MUST still check the chain link and the signature for it, and MUST NOT
require its content to match its hash.

Enforced retention requires deleting old personal data (GDPR Art. 5/17); the ledger is
hash-chained, so deleting a row breaks every row after it. Tombstoning resolves the apparent
contradiction: the link and the authenticated original hash remain, so the chain stays continuous
and attributable across an erasure, while the content that retention requires gone is gone.

#### Scenario: A tombstoned entry keeps the chain verifiable
- **WHEN** an entry is tombstoned (content erased, skeleton kept) and the chain is verified
- **THEN** verification succeeds, treating the tombstoned entry as an authenticated link
- **AND** a test tombstones a middle entry and asserts the whole chain still verifies

#### Scenario: Tampering is still caught on tombstoned rows
- **WHEN** a tombstoned entry's previous-hash link or signature is corrupted
- **THEN** verification fails at that entry
- **AND** separate tests corrupt the link and the signature of a tombstoned row, so waiving the
  content-recompute does not silently waive the other checks — the gap that once hid the original
  signature bug must not reopen

#### Scenario: Verification reports how much was erased
- **WHEN** a chain containing tombstoned entries is verified
- **THEN** the result reports the count of tombstoned entries
- **AND** a caller can tell "erased under retention" from "silently missing"

### Requirement: Retention classes bound age, and investigation holds override
Each retention class MUST bound the maximum age of an entry, and an investigation-class entry MUST
be exempt from routine purge. The purge job MUST tombstone entries past their class's age and MUST
NOT tombstone held entries.

Routine telemetry and an entry under an open investigation have different lifetimes; purging
evidence in an investigation would be the wrong default and, for a legal hold, unlawful.

#### Scenario: Expired routine entries are purged, held entries are not
- **WHEN** purge runs with entries older than their class age, including an investigation-class one
- **THEN** the expired routine entries are tombstoned and the investigation-class entry is untouched
- **AND** a test asserts both

### Requirement: An excluded subject produces no event
The producing path MUST NOT emit an event for a subject matching a configured exclusion (a
personal-folder path, a break-time window) — exclusion is at the source, before classification, so
no personal data about it is created.

The honest way not to surveil something is not to look at it. Redacting after the fact still means
the content was read and existed in memory; declining to produce the event means it never did. The
operator owns the exclusion list, so it is a privacy control, not a user-invokable DLP evasion.

#### Scenario: An excluded path is not classified
- **WHEN** a subject whose path matches an exclusion is presented to the producing path
- **THEN** no event is produced and classification never runs for it
- **AND** a test asserts the exclusion predicate and that an excluded subject yields no event

### Requirement: A view of an investigation is recordable as a tamper-evident entry
The ledger MUST provide a mechanism to record that an investigation was viewed and by whom, as an
ordinary chained entry so the view itself is tamper-evident. The recorded viewer MUST be labelled
unauthenticated until authenticated identity exists (T-017).

D20 requires the trail cover who VIEWED, not only who acted — browsing personal data is an
accountable action. Honest boundary discovered in implementation: recording a view is an APPEND,
which needs the signing key, and the query CLI is a pure verifier that must hold no signer (D30) —
a read-only process holding the key would break the very asymmetry that lets anyone verify without
being able to forge. So the mechanism lives on the write-capable ledger, and wiring it behind a
read surface belongs to the write-capable query service (T-023), not the signer-less CLI. Building
the mechanism now, and stating why it is not wired to the CLI, keeps the accountability seam real
without pretending an identity or a writer exists that does not.

#### Scenario: The ledger records a view as a labelled chained entry
- **WHEN** a view is recorded on the write-capable ledger with an unauthenticated OS-user label
- **THEN** an audit entry is appended marking it a view, carrying the label, and the chain still
  verifies
- **AND** a test asserts the entry, the label, and that recording it does not break verification

#### Scenario: The signer-less verifier cannot record a view
- **WHEN** a view-record is attempted on a ledger opened for verification only
- **THEN** it fails rather than silently succeeding, because appending needs the signing key the
  verifier must not hold

### Requirement: The pseudonymisation and purpose properties are pinned
The subject identifier crossing the host boundary MUST be pseudonymous, and every event MUST carry
a purpose tag. Tests MUST pin both so a regression is caught.

These are existing properties (D23, D20) that this change does not reimplement but does lock down —
an unpinned invariant rots silently, and these two are load-bearing for the legal basis of the
whole system.

#### Scenario: Pseudonymous subject and purpose are asserted
- **WHEN** the boundary-crossing summary and an event are inspected
- **THEN** the subject is a pseudonymous id, not a raw identity, and the purpose is set
- **AND** tests assert both

