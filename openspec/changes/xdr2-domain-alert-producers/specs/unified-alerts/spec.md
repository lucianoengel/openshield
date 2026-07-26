## ADDED Requirements

### Requirement: Every domain's decisions are projected into the unified stream

When the control plane persists a VERIFIED `decision`, it SHALL project that decision into the unified
alert stream, so the stream carries every producer's domain (endpoint DLP/HIPS, gateway network/DNS/SMTP,
and the ZT access proxy) rather than only server-side peer-UEBA. A decision whose action is
`ACTION_ALLOW` or `ACTION_UNSPECIFIED` SHALL NOT produce an alert. The projection SHALL be one row per
decision id, deduplicated by the key `decision:<decision_id>`.

Only VERIFIED telemetry projects: a decision arriving on the unverified at-most-once path is not evidence
(D44) and SHALL NOT be projected.

#### Scenario: An enforcement decision becomes a unified alert
- **WHEN** a signed `event` and its `decision` carrying a non-ALLOW action are verified and persisted
- **THEN** exactly one `unified_alerts` row exists for that decision, keyed to the event's entity

#### Scenario: An allowed decision is not an alert
- **WHEN** a verified `decision` carrying `ACTION_ALLOW` is persisted
- **THEN** no unified alert row is written for it
- **AND** the test that proves this FAILS if the ALLOW filter is removed from the projection

#### Scenario: A re-delivered decision is still one row
- **WHEN** the same verified decision is projected twice
- **THEN** exactly one unified-alert row exists for that decision id

### Requirement: The alert's entity and domain come from the originating event

A `Decision` carries neither a subject nor an event kind. The projection SHALL recover both from the
decision's ORIGINATING event — the already-persisted verified `event` row with the same `event_id` —
using `Event.Subject.PseudonymousId` as the entity key (D23) and `Event.Kind` as the domain source. It
SHALL NOT substitute the producing agent's id for the event subject: two domains observing the same host
must key to the same entity, which is what makes an entity JOIN a cross-domain grouping.

The `EventKind → domain` mapping SHALL be total over the closed enum: file and USB kinds map to `dlp`;
process-exec, ransomware-suspected, memory-injection-suspected and file-deleted map to `hips`;
network-flow, http-request, dns-query and smtp-message map to `nips`. An unmapped or unspecified kind
SHALL NOT be written under a guessed domain.

#### Scenario: Two domains on one host share one entity
- **WHEN** a HIPS `KILL_PROCESS` decision on a process-exec event and a network decision on a DNS-query
  event are ingested for the SAME event subject
- **THEN** both unified-alert rows carry the SAME `entity_id`, with domains `hips` and `nips`
- **AND** the test FAILS if the projection keys the alert by the producing agent id instead of the
  event's subject

#### Scenario: A decision with no persisted originating event
- **WHEN** a verified decision is ingested whose `event_id` matches no persisted verified event
- **THEN** no unified alert is written and the unprojected-decision counter increments

### Requirement: Severity is derived from the closed action set, and the title leaks nothing

Alert severity SHALL be derived from the decision's closed `Action` enum together with its confidence,
reusing the single existing risk→bucket mapping: enforcement actions (BLOCK, DENY_EXEC, KILL_PROCESS,
QUARANTINE_LOCAL, ENCRYPT_LOCAL, REDIRECT) take at least the `high` bucket; `ALERT` keeps the
confidence-derived bucket. Because the action set is CLOSED and TYPED (D14), this mapping is total — an
unmapped action is unexpressible rather than merely unhandled.

The alert title SHALL be composed ONLY from the closed `Action` and `EventKind` enum names. It SHALL NOT
carry the policy `reason` string, a file path, a host, a command line, a classifier identity, or any
matched content (D10/D29). This is proven by a test asserting the stored title against seeded
content-bearing decision/event fields — the title must contain none of them.

#### Scenario: An enforcement action outranks a low confidence
- **WHEN** a `KILL_PROCESS` decision with a low confidence is projected
- **THEN** the stored severity is at least `high`

#### Scenario: The title carries no content
- **WHEN** a decision with a content-bearing `reason` on an event with a content-bearing target is
  projected
- **THEN** the stored title contains neither the reason text nor any target field, only the enum-derived
  label

### Requirement: Projection is a derived index, never authoritative

The projection SHALL be best-effort (D38): a failure to resolve the entity, to find the originating
event, or to write the alert SHALL be counted and SHALL NOT change the ingest outcome for the decision,
roll back the persisted telemetry, or surface an error to the producer.

#### Scenario: A projection failure does not affect ingest
- **WHEN** the unified-alert write for a verified decision fails
- **THEN** the decision is still persisted, the ingest outcome is still "persisted", and a failure
  counter increments

### Requirement: Alert entity keying prefers an entity another domain already named

When keying a unified alert, the system SHALL first look up an EXISTING entity alias matching the
subject value regardless of alias kind, and only mint a new alias of the caller's kind when no alias
exists. A gateway ZT denial's subject is a USER identity that the access proxy has already linked to the
device entity; resolving it as a device alias would create a second, unlinked alias holding a user value
and fork that domain onto its own entity, which silently breaks cross-domain grouping.

#### Scenario: A user-subject alert joins the linked device entity
- **WHEN** the access proxy has linked device `D` and user `U` into one entity, and an alert is recorded
  for subject `U`
- **THEN** the alert's `entity_id` is the linked entity, the same one a device-subject alert for `D`
  resolves to
- **AND** the test FAILS if the kind-agnostic lookup is removed and the alert forks to a new entity

#### Scenario: An unknown subject still keys as a device
- **WHEN** an alert is recorded for a subject with no existing alias of any kind
- **THEN** a device alias is created for it and the alert keys to that entity, unchanged from prior
  behavior
