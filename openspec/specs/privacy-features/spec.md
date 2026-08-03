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


### Requirement: Retention purge is scheduled and runs automatically
The system MUST run the retention purge automatically on a periodic timer, not only expose it as a
library function. The local forward-secure ledger MUST purge by TOMBSTONING (erasing content while
keeping the chain skeleton verifiable), and the purge MUST run in the binaries that own a ledger.
Retention MUST NOT be indefinite.

#### Scenario: The ledger purge runs on a timer
- **WHEN** a binary that owns a local ledger has been running past the retention interval
- **THEN** it has invoked the ledger's retention purge, tombstoning bounded-class entries past their age

### Requirement: A data-subject access request compiles what is held about a subject
The control plane MUST compile, for one pseudonymous subject, a report of what the platform holds
about that subject across every subject-keyed store — the audit entries, the peer-UEBA alerts, the
investigation cases, and whether the subject is under a legal hold. A request with no subject id
MUST be refused, and a subject about whom nothing is held MUST return a well-formed empty report
rather than an error. The access surface MUST be operator-gated, and running a DSAR MUST be
recorded against the requesting operator's verified identity before the report is returned, so no
unattributable access to a subject's data occurs.

#### Scenario: A DSAR compiles a subject's records and is itself recorded
- **WHEN** an operator requests the data held about a pseudonymous subject
- **THEN** a report is returned summarizing that subject's audit entries, alerts, cases, and legal-hold status — scoped to that subject alone — the access is recorded against the operator's verified identity, and a subjectless request is refused while a subject with no records yields an empty report

### Requirement: An exclusion is configurable, and refused when unusable

The exclusion set SHALL be configurable on the agent — path prefixes and daily local-time windows —
and SHALL be validated when it is read. A malformed window, an empty window whose start equals its
end, or a window that crosses midnight SHALL be refused, naming the offending window, and the
component SHALL NOT start with a partial exclusion set.

A predicate with no way to configure it is not a control. A silently-dropped window is worse than
none: the operator wrote a break into the configuration, told a works council about it, and the agent
observed straight through it with nothing anywhere saying so.

A window crossing midnight is refused rather than split, because the interval is a half-open
[start, end) comparison on minutes since midnight and a crossing window matches nothing — the same
silent failure in a different shape.

#### Scenario: A malformed window refuses the configuration
- **WHEN** an exclusion window is not `HH:MM-HH:MM`, is out of range, has equal start and end, or
  crosses midnight
- **THEN** it is refused with the offending window named, and no exclusions are installed

#### Scenario: A configured window excludes exactly its interval
- **WHEN** a `12:00-13:00` window is configured
- **THEN** 12:00 and 12:59 are excluded and 11:59 and 13:00 are not

### Requirement: An exclusion window is evaluated in local time

An exclusion window SHALL be evaluated against the event's LOCAL time.

The window is expressed as a wall-clock interval an operator agreed with a works council. Evaluating
it against UTC would still exclude an hour a day — the wrong hour — and nothing about the running
system would look broken.

#### Scenario: A break window applies at the operator's clock
- **WHEN** an event is observed at 12:30 local time under a 12:00-13:00 window
- **THEN** it is excluded, whatever the host's offset from UTC

### Requirement: An exclusion never suppresses an enforcement verdict

An exclusion SHALL apply to the observation path only. A producer that asks the pipeline for a verdict
it will act on — an execution gate, a clipboard mediator, a print or mail decider — SHALL receive a
decision regardless of any configured exclusion.

A suppressed verdict necessarily resolves to allow, so an exclusion applied there would turn a
break-time window into a nightly interval in which anything runs, reachable by any user willing to
wait for it. The exclusion set is a privacy control, not a user-invokable evasion, and suppressing a
verdict is that evasion.

#### Scenario: A verdict is decided for an excluded subject
- **WHEN** a verdict is requested for a subject matching both a path exclusion and a time window
- **THEN** a decision is produced and classification runs, and no exclusion is counted

### Requirement: An unevaluable exclusion is counted rather than guessed

The system SHALL count and report every file event that a configured path exclusion could not be
evaluated against because the subject identity carries no resolvable path, and SHALL observe such an
event. It SHALL NOT be silently excluded, and SHALL NOT be silently observed.

An event that is not about a file SHALL NOT be counted: a personal-folder exclusion was never
applicable to it, and counting it would report a hole far larger than the one that exists.

The count is the size of the gap in the claim "these folders are not observed". A privacy control with
an unmeasured blind spot is a false statement to the people it was agreed with.

#### Scenario: A path-less file event is counted
- **WHEN** a path exclusion is configured and a file event carries a subject identity with no path
- **THEN** the event is not excluded, and the unevaluable count increases

#### Scenario: A non-file event is not counted as a gap
- **WHEN** a path exclusion is configured and a network event is observed
- **THEN** the unevaluable count does not increase

#### Scenario: A time window is never unevaluable
- **WHEN** a time window is configured and a file event carrying no path is observed inside it
- **THEN** it is excluded and the unevaluable count does not increase
